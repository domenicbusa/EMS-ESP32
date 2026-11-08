#include "MqttSettingsService.h"

#include <emsesp.h>

#ifndef EMSESP_STANDALONE
#include <mbedtls/base64.h>
#include <cstdarg>
#include <memory>
#include <string>
#endif

MqttSettingsService::MqttSettingsService(AsyncWebServer * server, FS * fs, SecurityManager * securityManager)
    : _httpEndpoint(MqttSettings::read, MqttSettings::update, this, server, MQTT_SETTINGS_SERVICE_PATH, securityManager)
    , _fsPersistence(MqttSettings::read, MqttSettings::update, this, fs, MQTT_SETTINGS_FILE)
    , _reconfigureMqtt(false)
    , _disconnectedAt(0)
    , _disconnectReason(espMqttClientTypes::DisconnectReason::USER_OK)
    , _mqttClient(nullptr) {
    addUpdateHandler([this] { onConfigUpdated(); }, false);
}

static String generateClientId() {
#ifdef EMSESP_STANDALONE
    return "ems-esp";
#else
    return "esp32-" + String(static_cast<uint32_t>(ESP.getEfuseMac()), HEX);
#endif
}

MqttSettingsService::~MqttSettingsService() {
    delete _mqttClient;
    _mqttClient = nullptr;
}

void MqttSettingsService::begin() {
    _fsPersistence.readFromFS();
    startClient();
    _reconfigureMqtt = true;
}

void MqttSettingsService::startClient() {
    static bool     isSecure  = false;
    static uint32_t stackSize = EMC_TASK_STACK_SIZE;
    // only verifying a CA chain needs the larger stack, insecure TLS and plain MQTT fit in the default
    const uint32_t wantStack = (_state.enableTLS && _state.rootCA != "insecure") ? EMSESP_MQTT_STACKSIZE_CA : EMC_TASK_STACK_SIZE;
    if (_mqttClient) {
        // do we need to change the client?
        if (isSecure == _state.enableTLS && stackSize == wantStack) {
            return;
        }

        delete _mqttClient;
        _mqttClient     = nullptr;
        _clientIsSecure = false;
    }

    stackSize = wantStack;

    if (_state.enableTLS) {
        isSecure        = true;
        _clientIsSecure = true;
        if (emsesp::EMSESP::system_.PSram() == 0) {
            _mqttClient = new espMqttClientSecure(espMqttClientTypes::UseInternalTask::NO);
        } else {
            _mqttClient = new espMqttClientSecure(EMSESP_MQTT_PRIORITY, EMSESP_MQTT_RUNNING_CORE, wantStack);
        }

        if (!_mqttClient) {
            emsesp::EMSESP::logger().warning("MQTT Client alloc failed");
            return;
        }

        static_cast<espMqttClientSecure *>(_mqttClient)->onConnect([this](bool sessionPresent) { onMqttConnect(sessionPresent); });
        static_cast<espMqttClientSecure *>(_mqttClient)->onDisconnect([this](espMqttClientTypes::DisconnectReason reason) { onMqttDisconnect(reason); });
        static_cast<espMqttClientSecure *>(_mqttClient)
            ->onMessage(
                [this](const espMqttClientTypes::MessageProperties & properties, const char * topic, const uint8_t * payload, size_t len, size_t index, size_t total) {
                    onMqttMessage(properties, topic, payload, len, index, total);
                });
        return;
    }

    isSecure        = false;
    _clientIsSecure = false;
    if (emsesp::EMSESP::system_.PSram() == 0) {
        _mqttClient = new espMqttClient(espMqttClientTypes::UseInternalTask::NO);
    } else {
        _mqttClient = new espMqttClient(EMSESP_MQTT_PRIORITY, EMSESP_MQTT_RUNNING_CORE);
    }

    static_cast<espMqttClient *>(_mqttClient)->onConnect([this](bool sessionPresent) { onMqttConnect(sessionPresent); });
    static_cast<espMqttClient *>(_mqttClient)->onDisconnect([this](espMqttClientTypes::DisconnectReason reason) { onMqttDisconnect(reason); });
    static_cast<espMqttClient *>(_mqttClient)
        ->onMessage(
            [this](const espMqttClientTypes::MessageProperties & properties, const char * topic, const uint8_t * payload, size_t len, size_t index, size_t total) {
                onMqttMessage(properties, topic, payload, len, index, total);
            });
}

void MqttSettingsService::loop() {
    if (_state.enabled && _mqttClient && _mqttClient->connected() && !emsesp::EMSESP::network_.network_connected()) {
        // emsesp::EMSESP::logger().info("Network connection dropped, stopping MQTT client");
        _mqttClient->disconnect(true);
    }

    if (_reconfigureMqtt || (_disconnectedAt && static_cast<uint32_t>(uuid::get_uptime() - _disconnectedAt) >= MQTT_RECONNECTION_DELAY)) {
        // configure MQTT client
        if (_reconfigureMqtt && _state.enabled) {
            emsesp::EMSESP::logger().info("Starting MQTT service");
        }

        _disconnectedAt  = configureMqtt() ? 0 : uuid::get_uptime();
        _reconfigureMqtt = false;
    }

    if (emsesp::EMSESP::system_.PSram() == 0) {
        _mqttClient->loop();
    }
}

bool MqttSettingsService::isEnabled() {
    return _state.enabled;
}

bool MqttSettingsService::isConnected() {
    return _mqttClient ? _mqttClient->connected() : false;
}

const char * MqttSettingsService::getClientId() {
    return _mqttClient ? _mqttClient->getClientId() : "";
}

void MqttSettingsService::onMqttMessage(const espMqttClientTypes::MessageProperties & properties,
                                        const char *                                  topic,
                                        const uint8_t *                               payload,
                                        size_t                                        len,
                                        size_t                                        index,
                                        size_t                                        total) {
    (void)properties;
    (void)index;
    (void)total;
    emsesp::EMSESP::mqtt_.on_message(topic, payload, len);
}

espMqttClientTypes::DisconnectReason MqttSettingsService::getDisconnectReason() {
    return _disconnectReason;
}

MqttClient * MqttSettingsService::getMqttClient() {
    return _mqttClient;
}

void MqttSettingsService::onMqttConnect(bool sessionPresent) {
    (void)sessionPresent;
    logConnected();
    emsesp::EMSESP::mqtt_.on_connect();
    _disconnectReason = espMqttClientTypes::DisconnectReason::USER_OK;
}

void MqttSettingsService::onMqttDisconnect(espMqttClientTypes::DisconnectReason reason) {
    logConnectFailure(reason); // every attempt, rate-limited

    if (reason != _disconnectReason) {
        emsesp::EMSESP::mqtt_.on_disconnect(reason);
        _disconnectReason = reason;
    }

    if (!_disconnectedAt) {
        _disconnectedAt = uuid::get_uptime();
    }
}

void MqttSettingsService::onConfigUpdated() {
    _reconfigureMqtt = true;
    _disconnectedAt  = 0;

    startClient();
    emsesp::EMSESP::mqtt_.start(); // reload EMS-ESP MQTT settings
}

bool MqttSettingsService::configureMqtt() {
    const bool reconfigured = _reconfigureMqtt;

    // disconnect if already connected
    if (_mqttClient->connected()) {
#if defined(EMSESP_DEBUG)
        emsesp::EMSESP::logger().debug("Disconnecting to configure");
#endif
        _mqttClient->disconnect(true);
        if (!_state.enabled) {
            emsesp::EMSESP::logger().info("Stopping MQTT client");
        }
    }

    // only connect if WiFi is connected and MQTT is enabled
    if (_state.enabled && emsesp::EMSESP::network_.network_connected() && !_state.host.isEmpty()) {
        // create the Last Will Testament topic (LWT) with the base prefixed. It has to be static because the client destroys the reference
        static char will_topic[FACTORY_MQTT_MAX_TOPIC_LENGTH];
        if (_state.base.isEmpty()) {
            snprintf(will_topic, sizeof(will_topic), "status");
        } else {
            snprintf(will_topic, sizeof(will_topic), "%s/status", _state.base.c_str());
        }

        _reconfigureMqtt = false;
        logConnectAttempt(reconfigured);
        if (_state.enableTLS) {
            if (_state.rootCA == "insecure") {
#if defined(EMSESP_DEBUG)
                emsesp::EMSESP::logger().debug("Start insecure MQTT");
#endif
                static_cast<espMqttClientSecure *>(_mqttClient)->setInsecure();
            } else {
#if defined(EMSESP_DEBUG)
                emsesp::EMSESP::logger().debug("Start secure MQTT with rootCA");
#endif
                String certificate = "-----BEGIN CERTIFICATE-----\n" + _state.rootCA + "\n-----END CERTIFICATE-----\n";
                static_cast<espMqttClientSecure *>(_mqttClient)->setCACert(certificate.c_str());
            }

            static_cast<espMqttClientSecure *>(_mqttClient)->setServer(_state.host.c_str(), _state.port);
            if (_state.username.length() > 0) {
                static_cast<espMqttClientSecure *>(_mqttClient)
                    ->setCredentials(_state.username.c_str(), _state.password.length() > 0 ? _state.password.c_str() : nullptr);
            }

            static_cast<espMqttClientSecure *>(_mqttClient)->setClientId(_state.clientId.c_str());
            static_cast<espMqttClientSecure *>(_mqttClient)->setKeepAlive(_state.keepAlive);
            static_cast<espMqttClientSecure *>(_mqttClient)->setCleanSession(_state.cleanSession);
            static_cast<espMqttClientSecure *>(_mqttClient)->setWill(will_topic, 1, true, "offline"); // QOS 1, retain
            return (_mqttClient->connect());
        }

        static_cast<espMqttClient *>(_mqttClient)->setServer(_state.host.c_str(), _state.port);
        if (_state.username.length() > 0) {
            static_cast<espMqttClient *>(_mqttClient)->setCredentials(_state.username.c_str(), _state.password.length() > 0 ? _state.password.c_str() : nullptr);
        }

        static_cast<espMqttClient *>(_mqttClient)->setClientId(_state.clientId.c_str());
        static_cast<espMqttClient *>(_mqttClient)->setKeepAlive(_state.keepAlive);
        static_cast<espMqttClient *>(_mqttClient)->setCleanSession(_state.cleanSession);
        static_cast<espMqttClient *>(_mqttClient)->setWill(will_topic, 1, true, "offline"); // QOS 1, retain
        return (_mqttClient->connect());
    }

    return false;
}

// ---------------------------------------------------------------------------------------------------------------------
// MQTT connection logging
// ---------------------------------------------------------------------------------------------------------------------

#ifndef EMSESP_STANDALONE

// The logger cuts every line at 255 characters (uuid::log::Logger::MAX_LOG_LENGTH), which would lose the hints at the
// end of the longer messages, so long messages are wrapped over several lines at word boundaries
static void mqtt_log(uuid::log::Level level, const char * format, ...) {
    char    text[1024];
    va_list ap;
    va_start(ap, format);
    int len = vsnprintf(text, sizeof(text), format, ap);
    va_end(ap);
    if (len <= 0) {
        return;
    }
    len = std::min(len, static_cast<int>(sizeof(text)) - 1);

    constexpr int chunk = 230; // leaves room for the "  ..." continuation prefix
    int           pos   = 0;
    bool          first = true;
    while (pos < len) {
        int n = len - pos;
        if (n > chunk) {
            n = chunk;
            while (n > chunk / 2 && text[pos + n] != ' ') {
                n--; // break at a space if there is one in the second half of the chunk
            }
            if (text[pos + n] != ' ') {
                n = chunk; // no space: hard break
            }
        }
        emsesp::EMSESP::logger().log(level, first ? "%.*s" : "  ...%.*s", n, text + pos);
        pos += n;
        while (pos < len && text[pos] == ' ') {
            pos++;
        }
        first = false;
    }
}

// the system clock is set (NTP) if it's past the timestamp ESP_SSLClient itself uses as "valid"
static bool clock_is_set() {
    return time(nullptr) > ESP_SSLCLIENT_VALID_TIMESTAMP;
}

static bool host_is_ip(const String & host) {
    IPAddress ip;
    return ip.fromString(host.c_str());
}

static void format_date(time_t t, char * out, size_t len) {
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(out, len, "%Y-%m-%d", &tm);
}

// what the stored CA certificate contains, decoded with the BearSSL that ESP_SSLClient uses for the handshake
struct CaInfo {
    int    err       = 0; // 0 = decoded, -1 = not valid base64, else a BearSSL X.509 error code
    size_t der_len   = 0;
    bool   is_ca     = false;
    char   cn[65]    = "";
    char   key[24]   = "";
    time_t not_after = 0;
    time_t not_before = 0;
};

static void ca_append_dn(void * ctx, const void * buf, size_t len) {
    static_cast<std::string *>(ctx)->append(static_cast<const char *>(buf), len);
}

// pull the common name (OID 2.5.4.3) out of a DER encoded distinguished name
static void ca_find_cn(const std::string & dn, char * out, size_t outlen) {
    static const char oid_cn[] = {0x06, 0x03, 0x55, 0x04, 0x03};
    size_t            pos      = dn.find(std::string(oid_cn, sizeof(oid_cn)));
    if (pos == std::string::npos || pos + sizeof(oid_cn) + 2 > dn.size()) {
        return;
    }
    pos += sizeof(oid_cn) + 1; // skip the string tag (UTF8String, PrintableString, ...)
    size_t len = static_cast<uint8_t>(dn[pos++]);
    if (len >= 0x80 || pos + len > dn.size()) {
        return; // long-form length: not a plausible CN
    }
    len = std::min(len, outlen - 1);
    memcpy(out, dn.data() + pos, len);
    out[len] = '\0';
}

static CaInfo decode_ca(const String & b64) {
    CaInfo info;

    size_t der_len = 0;
    mbedtls_base64_decode(nullptr, 0, &der_len, reinterpret_cast<const unsigned char *>(b64.c_str()), b64.length());
    std::unique_ptr<uint8_t[]> der(new (std::nothrow) uint8_t[der_len + 1]);
    if (!der || mbedtls_base64_decode(der.get(), der_len + 1, &der_len, reinterpret_cast<const unsigned char *>(b64.c_str()), b64.length()) != 0) {
        info.err = -1;
        return info;
    }
    info.der_len = der_len;

    std::unique_ptr<br_x509_decoder_context> dc(new (std::nothrow) br_x509_decoder_context);
    if (!dc) {
        info.err = -1;
        return info;
    }
    std::string dn;
    br_x509_decoder_init(dc.get(), ca_append_dn, &dn);
    br_x509_decoder_push(dc.get(), der.get(), der_len);
    info.err = br_x509_decoder_last_error(dc.get());
    if (info.err) {
        return info;
    }

    info.is_ca = br_x509_decoder_isCA(dc.get());
    ca_find_cn(dn, info.cn, sizeof(info.cn));

    // BearSSL counts days from 0000-01-01, Unix time from 1970-01-01 (day 719528)
    info.not_before = static_cast<time_t>(dc->notbefore_days - 719528) * 86400 + dc->notbefore_seconds;
    info.not_after  = static_cast<time_t>(dc->notafter_days - 719528) * 86400 + dc->notafter_seconds;

    const br_x509_pkey * pk = br_x509_decoder_get_pkey(dc.get());
    if (pk && pk->key_type == BR_KEYTYPE_RSA) {
        snprintf(info.key, sizeof(info.key), "RSA %u-bit", static_cast<unsigned>(pk->key.rsa.nlen * 8));
    } else if (pk && pk->key_type == BR_KEYTYPE_EC) {
        snprintf(info.key,
                 sizeof(info.key),
                 "EC %s",
                 pk->key.ec.curve == BR_EC_secp256r1   ? "P-256"
                 : pk->key.ec.curve == BR_EC_secp384r1 ? "P-384"
                 : pk->key.ec.curve == BR_EC_secp521r1 ? "P-521"
                                                       : "other curve");
    }
    return info;
}

static void heap_info(char * out, size_t len) {
    snprintf(out, len, "heap %u KB free, largest block %u KB", ESP.getFreeHeap() / 1024, ESP.getMaxAllocHeap() / 1024);
}

#endif

// logged before each connect: where to, how, and as whom. First attempt and changed settings at INFO, retries at DEBUG
void MqttSettingsService::logConnectAttempt(bool reconfigured) {
#ifndef EMSESP_STANDALONE
    const char * mode = !_state.enableTLS              ? "plain MQTT, no TLS"
                        : _state.rootCA == "insecure" ? "TLS without certificate check (insecure)"
                                                      : "TLS, broker certificate checked against the CA";
    if (reconfigured || _failedAttempts == 0) {
        mqtt_log(uuid::log::Level::INFO, "MQTT connecting to %s:%u (%s), user '%s', client ID '%s'",
                                      _state.host.c_str(),
                                      _state.port,
                                      mode,
                                      _state.username.c_str(),
                                      _state.clientId.c_str());
        if (_state.enableTLS && _state.port == 1883) {
            mqtt_log(uuid::log::Level::WARNING, "MQTT TLS is on but port is 1883, the usual plain MQTT port. TLS brokers normally listen on 8883");
        } else if (!_state.enableTLS && _state.port == 8883) {
            mqtt_log(uuid::log::Level::WARNING, "MQTT TLS is off but port is 8883, the usual TLS port. Turn on TLS?");
        }
        if (_state.enableTLS) {
            logTlsSetup();
        }
    } else {
        mqtt_log(uuid::log::Level::DEBUG, "MQTT reconnecting to %s:%u, attempt %u", _state.host.c_str(), _state.port, _failedAttempts + 1);
    }
#else
    (void)reconfigured;
#endif
}

// what the TLS check is going to work with, and the known ways it fails before it even starts
void MqttSettingsService::logTlsSetup() {
#ifndef EMSESP_STANDALONE

    if (!clock_is_set()) {
        mqtt_log(uuid::log::Level::WARNING, "MQTT TLS: the clock isn't set yet (NTP). Certificate dates can't be checked until it is, so a TLS connect with a CA will fail until "
                    "NTP syncs");
    }

    if (_state.rootCA == "insecure") {
        mqtt_log(uuid::log::Level::WARNING, "MQTT TLS: no CA certificate set, the broker's certificate is NOT checked (encrypted, but not authenticated)");
        return;
    }

    CaInfo ca = decode_ca(_state.rootCA);
    if (ca.err == -1) {
        mqtt_log(uuid::log::Level::ERR, "MQTT TLS: the CA certificate is not valid base64. Paste the whole PEM, including the BEGIN/END CERTIFICATE lines");
        return;
    }
    if (ca.err) {
        mqtt_log(uuid::log::Level::ERR, "MQTT TLS: the CA certificate could not be decoded (BearSSL X.509 error %d, %u bytes). Paste exactly one PEM certificate",
                ca.err,
                static_cast<unsigned>(ca.der_len));
        return;
    }

    char from[12], until[12];
    format_date(ca.not_before, from, sizeof(from));
    format_date(ca.not_after, until, sizeof(until));
    mqtt_log(uuid::log::Level::INFO, "MQTT TLS: CA certificate CN='%s', %s, %s, valid %s to %s",
             ca.cn,
             ca.key[0] ? ca.key : "unknown key type",
             ca.is_ca ? "CA" : "not a CA (only works if it is the broker's own self-signed certificate)",
             from,
             until);

    if (clock_is_set()) {
        time_t now = time(nullptr);
        if (now < ca.not_before) {
            mqtt_log(uuid::log::Level::ERR, "MQTT TLS: the CA certificate is not valid until %s", from);
        } else if (now > ca.not_after) {
            mqtt_log(uuid::log::Level::ERR, "MQTT TLS: the CA certificate expired on %s", until);
        }
    }

    // BearSSL checks the host name against the DNS names and CN of the broker's certificate. It has no IP address matching
    if (host_is_ip(_state.host)) {
        mqtt_log(uuid::log::Level::WARNING, "MQTT TLS: host '%s' is an IP address. The certificate check matches DNS names only, so this fails unless the broker certificate "
                    "lists '%s' as a DNS name. Use a DNS host name that is in the certificate",
                    _state.host.c_str(),
                    _state.host.c_str());
    } else if (ca.cn[0] && !_state.host.equalsIgnoreCase(ca.cn) && !ca.is_ca) {
        mqtt_log(uuid::log::Level::WARNING, "MQTT TLS: host '%s' is not the certificate's CN '%s'. It must be one of the certificate's DNS names, or the check fails",
                    _state.host.c_str(),
                    ca.cn);
    }
#endif
}

// every failed connect: which stage failed, why, and what to look at. Rate-limited when it keeps failing the same way
void MqttSettingsService::logConnectFailure(espMqttClientTypes::DisconnectReason reason) {
#ifndef EMSESP_STANDALONE
    using espMqttClientTypes::DisconnectReason;
    using Stage = espMqttClientInternals::ConnectDiag::Stage;

    if (reason == DisconnectReason::USER_OK) {
        _connectedAt = 0;
        return; // our own disconnect, e.g. to apply new settings
    }

    const uint32_t was_connected_s = _connectedAt ? (uuid::get_uptime() - _connectedAt) / 1000 : 0;
    const bool     was_connected   = _connectedAt != 0;
    _connectedAt                   = 0;
    _failedAttempts++;

    char msg[640];
    char heap[48];
    heap_info(heap, sizeof(heap));

    const bool secure = isSecureClient();
    Stage      stage  = Stage::NONE;
    if (secure) {
        const auto & d = static_cast<espMqttClientSecure *>(_mqttClient)->connectDiag();
        stage          = d.stage;
        char ip[16];
        snprintf(ip, sizeof(ip), "%s", d.ip.toString().c_str());

        switch (d.stage) {
        case Stage::DNS:
            snprintf(msg, sizeof(msg), "DNS lookup of '%s' failed (%u ms). Check the host name and the DNS server", _state.host.c_str(), d.dns_ms);
            break;
        case Stage::TCP:
            snprintf(msg,
                     sizeof(msg),
                     "TCP connect to %s:%u (%s) failed: %s (%u ms). Is the broker up, the port right, and nothing blocking it?",
                     _state.host.c_str(),
                     _state.port,
                     ip,
                     d.sock_errno ? strerror(d.sock_errno) : "no answer",
                     d.tcp_ms);
            break;
        case Stage::TLS: {
            int n = snprintf(msg,
                             sizeof(msg),
                             "TLS handshake with %s:%u (%s) failed after %u ms (TCP was fine).",
                             _state.host.c_str(),
                             _state.port,
                             ip,
                             d.tls_ms);
            if (n > 0 && _state.rootCA != "insecure") {
                if (!clock_is_set()) {
                    n += snprintf(msg + n, sizeof(msg) - n, " Clock not set (NTP), so the certificate can't be checked yet.");
                } else if (host_is_ip(_state.host)) {
                    n += snprintf(msg + n, sizeof(msg) - n, " Likely cause: host is an IP address, which the certificate name check can't match.");
                } else {
                    n += snprintf(msg + n,
                                  sizeof(msg) - n,
                                  " Check the CA is the one that signed the broker certificate and '%s' is one of its names.",
                                  _state.host.c_str());
                }
            }
            if (n > 0 && d.rx_buffer < 16384) {
                snprintf(msg + n, sizeof(msg) - n, " TLS buffer is %u bytes (no PSRAM): the broker must support max fragment length.", d.rx_buffer);
            }
            break;
        }
        default:
            msg[0] = '\0';
            break;
        }
    }

    // the transport worked (or isn't instrumented): the MQTT layer or the broker ended it
    if (!secure || stage == Stage::OK || stage == Stage::NONE) {
        switch (reason) {
        case DisconnectReason::MQTT_NOT_AUTHORIZED:
        case DisconnectReason::MQTT_MALFORMED_CREDENTIALS:
            snprintf(msg,
                     sizeof(msg),
                     "broker refused the login: %s. Check username '%s' and the password",
                     espMqttClientTypes::disconnectReasonToString(reason),
                     _state.username.c_str());
            break;
        case DisconnectReason::MQTT_IDENTIFIER_REJECTED:
            snprintf(msg, sizeof(msg), "broker rejected client ID '%s'", _state.clientId.c_str());
            break;
        case DisconnectReason::MQTT_UNACCEPTABLE_PROTOCOL_VERSION:
        case DisconnectReason::MQTT_SERVER_UNAVAILABLE:
        case DisconnectReason::TLS_BAD_FINGERPRINT:
            snprintf(msg, sizeof(msg), "broker refused the connection: %s", espMqttClientTypes::disconnectReasonToString(reason));
            break;
        default: // TCP_DISCONNECTED
            if (was_connected) {
                snprintf(msg,
                         sizeof(msg),
                         "connection lost after %u s. If it keeps happening, check the broker log: another client using client ID '%s', or the network",
                         was_connected_s,
                         _state.clientId.c_str());
            } else if (secure) {
                snprintf(msg,
                         sizeof(msg),
                         "broker closed the connection before accepting the MQTT login. Check the broker log for user '%s'",
                         _state.username.c_str());
            } else {
                snprintf(msg, sizeof(msg), "can't connect to %s:%u (DNS, TCP or broker)", _state.host.c_str(), _state.port);
            }
            break;
        }
    }

    // log the first few, then every 10th, and always when the failure changes
    const bool changed = !_lastFailure.equals(msg);
    if (_failedAttempts <= 3 || (_failedAttempts % 10) == 0 || changed) {
        mqtt_log(uuid::log::Level::ERR, "MQTT connection failed (attempt %u): %s [%s]. Retrying...", _failedAttempts, msg, heap);
        _lastFailure = msg;
    }
#else
    (void)reason;
#endif
}

// a successful connect, with how it went
void MqttSettingsService::logConnected() {
#ifndef EMSESP_STANDALONE
    char heap[48];
    heap_info(heap, sizeof(heap));
    if (isSecureClient()) {
        const auto & d = static_cast<espMqttClientSecure *>(_mqttClient)->connectDiag();
        mqtt_log(uuid::log::Level::INFO, "MQTT connected to %s:%u (%s) over TLS (%s), DNS %u ms, TCP %u ms, TLS %u ms, max fragment length %s, after %u failed "
                                      "attempts [%s]",
                                      _state.host.c_str(),
                                      _state.port,
                                      d.ip.toString().c_str(),
                                      _state.rootCA == "insecure" ? "certificate NOT checked" : "certificate checked",
                                      d.dns_ms,
                                      d.tcp_ms,
                                      d.tls_ms,
                                      d.mfln ? "negotiated" : "not negotiated",
                                      _failedAttempts,
                                      heap);
    } else {
        mqtt_log(uuid::log::Level::INFO, "MQTT connected to %s:%u (plain MQTT, no TLS), after %u failed attempts [%s]", _state.host.c_str(), _state.port, _failedAttempts, heap);
    }
    _failedAttempts = 0;
    _lastFailure    = "";
    _connectedAt    = uuid::get_uptime();
    if (_connectedAt == 0) {
        _connectedAt = 1; // 0 means "not connected"
    }
#endif
}

void MqttSettings::read(MqttSettings & settings, JsonObject root) {
    root["enableTLS"]     = settings.enableTLS;
    root["rootCA"]        = settings.rootCA;
    root["enabled"]       = settings.enabled;
    root["host"]          = settings.host;
    root["port"]          = settings.port;
    root["base"]          = settings.base;
    root["username"]      = settings.username;
    root["password"]      = settings.password;
    root["client_id"]     = settings.clientId;
    root["keep_alive"]    = settings.keepAlive;
    root["clean_session"] = settings.cleanSession;
    root["entity_format"] = settings.entity_format;

    root["publish_time_boiler"]     = settings.publish_time_boiler;
    root["publish_time_thermostat"] = settings.publish_time_thermostat;
    root["publish_time_solar"]      = settings.publish_time_solar;
    root["publish_time_mixer"]      = settings.publish_time_mixer;
    root["publish_time_water"]      = settings.publish_time_water;
    root["publish_time_other"]      = settings.publish_time_other;
    root["publish_time_sensor"]     = settings.publish_time_sensor;
    root["publish_time_heartbeat"]  = settings.publish_time_heartbeat;
    root["mqtt_qos"]                = settings.mqtt_qos;
    root["mqtt_retain"]             = settings.mqtt_retain;
    root["ha_enabled"]              = settings.ha_enabled;
    root["nested_format"]           = settings.nested_format;
    root["discovery_prefix"]        = settings.discovery_prefix;
    root["discovery_type"]          = settings.discovery_type;
    root["ha_number_mode"]          = settings.ha_number_mode;
    root["publish_single"]          = settings.publish_single;
    root["publish_single2cmd"]      = settings.publish_single2cmd;
    root["send_response"]           = settings.send_response;
    root["telemetry_readings"]      = settings.telemetry_readings;
}

StateUpdateResult MqttSettings::update(JsonObject root, MqttSettings & settings) {
    MqttSettings newSettings;
    bool         changed = false;

    newSettings.enableTLS    = root["enableTLS"];
    newSettings.rootCA       = root["rootCA"] | "";
    newSettings.enabled      = root["enabled"] | FACTORY_MQTT_ENABLED;
    newSettings.host         = root["host"] | FACTORY_MQTT_HOST;
    newSettings.port         = static_cast<uint16_t>(root["port"] | FACTORY_MQTT_PORT);
    newSettings.base         = root["base"] | FACTORY_MQTT_BASE;
    newSettings.username     = root["username"] | FACTORY_MQTT_USERNAME;
    newSettings.password     = root["password"] | FACTORY_MQTT_PASSWORD;
    newSettings.clientId     = root["client_id"] | generateClientId();
    newSettings.keepAlive    = static_cast<uint16_t>(root["keep_alive"] | FACTORY_MQTT_KEEP_ALIVE);
    newSettings.cleanSession = root["clean_session"] | FACTORY_MQTT_CLEAN_SESSION;
    newSettings.mqtt_qos     = static_cast<uint8_t>(root["mqtt_qos"] | EMSESP_DEFAULT_MQTT_QOS);
    newSettings.mqtt_retain  = root["mqtt_retain"] | EMSESP_DEFAULT_MQTT_RETAIN;

    newSettings.publish_time_boiler     = static_cast<uint16_t>(root["publish_time_boiler"] | EMSESP_DEFAULT_PUBLISH_TIME);
    newSettings.publish_time_thermostat = static_cast<uint16_t>(root["publish_time_thermostat"] | EMSESP_DEFAULT_PUBLISH_TIME);
    newSettings.publish_time_solar      = static_cast<uint16_t>(root["publish_time_solar"] | EMSESP_DEFAULT_PUBLISH_TIME);
    newSettings.publish_time_mixer      = static_cast<uint16_t>(root["publish_time_mixer"] | EMSESP_DEFAULT_PUBLISH_TIME);
    newSettings.publish_time_water      = static_cast<uint16_t>(root["publish_time_water"] | EMSESP_DEFAULT_PUBLISH_TIME);
    newSettings.publish_time_other      = static_cast<uint16_t>(root["publish_time_other"] | EMSESP_DEFAULT_PUBLISH_TIME_OTHER);
    newSettings.publish_time_sensor     = static_cast<uint16_t>(root["publish_time_sensor"] | EMSESP_DEFAULT_PUBLISH_TIME);
    newSettings.publish_time_heartbeat  = static_cast<uint16_t>(root["publish_time_heartbeat"] | EMSESP_DEFAULT_PUBLISH_HEARTBEAT);

    newSettings.ha_enabled         = root["ha_enabled"] | EMSESP_DEFAULT_HA_ENABLED;
    newSettings.nested_format      = static_cast<uint8_t>(root["nested_format"] | EMSESP_DEFAULT_NESTED_FORMAT);
    newSettings.discovery_prefix   = root["discovery_prefix"] | EMSESP_DEFAULT_DISCOVERY_PREFIX;
    newSettings.discovery_type     = static_cast<uint8_t>(root["discovery_type"] | EMSESP_DEFAULT_DISCOVERY_TYPE);
    newSettings.ha_number_mode     = static_cast<uint8_t>(root["ha_number_mode"] | EMSESP_DEFAULT_HA_NUMBER_MODE);
    newSettings.publish_single     = root["publish_single"] | EMSESP_DEFAULT_PUBLISH_SINGLE;
    newSettings.publish_single2cmd = root["publish_single2cmd"] | EMSESP_DEFAULT_PUBLISH_SINGLE2CMD;
    newSettings.send_response      = root["send_response"] | EMSESP_DEFAULT_SEND_RESPONSE;
    newSettings.telemetry_readings = root["telemetry_readings"] | EMSESP_DEFAULT_TELEMETRY_READINGS;
    newSettings.entity_format      = static_cast<uint8_t>(root["entity_format"] | EMSESP_DEFAULT_ENTITY_FORMAT);

    if (newSettings.enabled != settings.enabled) {
        changed = true;
    }

    if (newSettings.mqtt_qos != settings.mqtt_qos) {
        emsesp::EMSESP::mqtt_.set_qos(newSettings.mqtt_qos);
        changed = true;
    }

    if (newSettings.nested_format != settings.nested_format) {
        changed = true;
    }

    if (newSettings.discovery_prefix != settings.discovery_prefix) {
        changed = true;
    }

    if (newSettings.discovery_type != settings.discovery_type) {
        changed = true;
    }

    if (newSettings.ha_number_mode != settings.ha_number_mode) {
        changed = true;
    }

    if (newSettings.entity_format != settings.entity_format) {
        changed = true;
    }

    // telemetry readings replace the regular device topics, so HA discovery and single-value topics make no sense with it
    if (newSettings.telemetry_readings) {
        newSettings.ha_enabled     = false;
        newSettings.publish_single = false;
    }

    if (newSettings.telemetry_readings != settings.telemetry_readings) {
        changed = true;
    }

    //  if both settings are stored from older version, HA has priority
    if (newSettings.ha_enabled && newSettings.publish_single) {
        newSettings.publish_single = false;
    }

    if (newSettings.publish_single != settings.publish_single) {
        if (newSettings.publish_single) {
            newSettings.ha_enabled = false;
        }

        changed = true;
    }

    if (newSettings.publish_single2cmd != settings.publish_single2cmd) {
        changed = true;
    }

    if (newSettings.send_response != settings.send_response) {
        changed = true;
    }

    if (newSettings.ha_enabled != settings.ha_enabled) {
        emsesp::EMSESP::mqtt_.ha_enabled(newSettings.ha_enabled);
        if (newSettings.ha_enabled) {
            newSettings.publish_single = false;
        }

        changed = true;
    }

    if (newSettings.mqtt_retain != settings.mqtt_retain) {
        emsesp::EMSESP::mqtt_.set_retain(newSettings.mqtt_retain);
        changed = true;
    }

    if (newSettings.publish_time_boiler != settings.publish_time_boiler) {
        emsesp::EMSESP::mqtt_.set_publish_time_boiler(newSettings.publish_time_boiler);
    }

    if (newSettings.publish_time_thermostat != settings.publish_time_thermostat) {
        emsesp::EMSESP::mqtt_.set_publish_time_thermostat(newSettings.publish_time_thermostat);
    }

    if (newSettings.publish_time_solar != settings.publish_time_solar) {
        emsesp::EMSESP::mqtt_.set_publish_time_solar(newSettings.publish_time_solar);
    }

    if (newSettings.publish_time_mixer != settings.publish_time_mixer) {
        emsesp::EMSESP::mqtt_.set_publish_time_mixer(newSettings.publish_time_mixer);
    }

    if (newSettings.publish_time_water != settings.publish_time_water) {
        emsesp::EMSESP::mqtt_.set_publish_time_water(newSettings.publish_time_water);
    }

    if (newSettings.publish_time_other != settings.publish_time_other) {
        emsesp::EMSESP::mqtt_.set_publish_time_other(newSettings.publish_time_other);
    }

    if (newSettings.publish_time_sensor != settings.publish_time_sensor) {
        emsesp::EMSESP::mqtt_.set_publish_time_sensor(newSettings.publish_time_sensor);
    }

    if (newSettings.publish_time_heartbeat != settings.publish_time_heartbeat) {
        emsesp::EMSESP::mqtt_.set_publish_time_heartbeat(newSettings.publish_time_heartbeat);
    }

    // strip down to certificate only
    newSettings.rootCA.replace("\r", "");
    newSettings.rootCA.replace("\n", "");
    newSettings.rootCA.replace("-----BEGIN CERTIFICATE-----", "");
    newSettings.rootCA.replace("-----END CERTIFICATE-----", "");
    newSettings.rootCA.replace(" ", "");
    if (newSettings.rootCA.length() == 0 && newSettings.enableTLS) {
        newSettings.rootCA = "insecure";
    }

    if (newSettings.enableTLS != settings.enableTLS || newSettings.rootCA != settings.rootCA) {
        changed = true;
    }

    // save the new settings
    settings = newSettings;

    if (changed) {
        emsesp::EMSESP::mqtt_.reset_mqtt();
    }

    return StateUpdateResult::CHANGED;
}
