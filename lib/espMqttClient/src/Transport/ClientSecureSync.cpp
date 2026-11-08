/*
Copyright (c) 2022 Bert Melis. All rights reserved.

This work is licensed under the terms of the MIT license.  
For a copy, see <https://opensource.org/licenses/MIT> or
the LICENSE file.
*/

#include "ClientSecureSync.h"
#include <lwip/sockets.h>
#include <Network.h> // Network.hostByName() works on both WiFi and Ethernet
#include "../Config.h"

namespace espMqttClientInternals {

ClientSecureSync::ClientSecureSync()
    : client() {
    client.setClient(&basic_client, true);
#if defined(BOARD_HAS_PSRAM) && defined(ENABLE_PSRAM)
    // A small receive buffer relies on the broker honouring the TLS max fragment length extension. Brokers that
    // ignore it send records of up to 16 KB, which fail the connection. With PSRAM the TLS buffers are allocated
    // there, so take a full-size receive buffer.
    _rxBufferSize = ESP.getPsramSize() > 0 ? 16384 : EMC_RX_BUFFER_SIZE;
#else
    _rxBufferSize = EMC_RX_BUFFER_SIZE;
#endif
    client.setBufferSizes(_rxBufferSize, EMC_TX_BUFFER_SIZE);
    client.setSessionTimeout(120); // Set the timeout in seconds (>=120 seconds)
}

ClientSecureSync::~ClientSecureSync() {
    stop();
}

// ESP_SSLClient::connect() only starts TLS on its built-in list of well-known ports (8883 among them) and stays
// plain TCP on any other port, which would send the MQTT credentials in clear. So the stages are run here instead:
// DNS lookup, TCP connect on the plain socket, then the TLS handshake with connectSSL(), which reuses the already
// connected socket. Each stage is recorded in diag so a failure can be logged with where and why it failed.
bool ClientSecureSync::connect(IPAddress ip, uint16_t port) {
    diag           = ConnectDiag();
    diag.rx_buffer = _rxBufferSize;
    diag.ip        = ip;
    return connectStages(nullptr, ip, port);
}

bool ClientSecureSync::connect(const char * host, uint16_t port) {
    diag           = ConnectDiag();
    diag.rx_buffer = _rxBufferSize;

    uint32_t  start = millis();
    IPAddress ip;
    if (!ip.fromString(host)) {
        if (!Network.hostByName(host, ip) || ip == IPAddress()) {
            diag.dns_ms = millis() - start;
            diag.stage  = ConnectDiag::Stage::DNS;
            return false;
        }
    }
    diag.dns_ms = millis() - start;
    diag.ip     = ip;

    // the host name, not the IP, goes to TLS: it's the name the broker certificate is checked against (and the SNI)
    return connectStages(host, ip, port);
}

bool ClientSecureSync::connectStages(const char * host, IPAddress ip, uint16_t port) {
    client.stop(); // drop anything left over from a previous connection

    uint32_t start = millis();
    errno          = 0;
    if (!basic_client.connect(ip, port)) {
        diag.tcp_ms     = millis() - start;
        diag.sock_errno = errno;
        diag.stage      = ConnectDiag::Stage::TCP;
        return false;
    }
    diag.tcp_ms = millis() - start;

    // TLS stage. client.connect() finds the socket already connected and goes straight to the handshake on the
    // well-known TLS ports; on any other port it only stores host/port and connectSSL() does the handshake.
    // connect() is used rather than connectSSL(host, port), because the latter ignores its arguments and uses the
    // host stored by connect(): the name the broker certificate is checked against.
    start   = millis();
    bool ok = (host ? client.connect(host, port) : client.connect(ip, port)) && (client.isSecure() || client.connectSSL());
    diag.tls_ms = millis() - start;
    if (!ok) {
        diag.stage = ConnectDiag::Stage::TLS;
        basic_client.stop();
        return false;
    }

    diag.stage = ConnectDiag::Stage::OK;
    diag.mfln  = client.getMFLNStatus();

    // Set TCP option directly to bypass lack of working setNoDelay for WiFiClientSecure
    int val = true;
    basic_client.setSocketOption(IPPROTO_TCP, TCP_NODELAY, &val, sizeof(int));
    return true;
}

size_t ClientSecureSync::write(const uint8_t * buf, size_t size) {
    return client.write(buf, size);
}

int ClientSecureSync::read(uint8_t * buf, size_t size) {
    return client.read(buf, size);
}

void ClientSecureSync::stop() {
    client.stop();
}

bool ClientSecureSync::connected() {
    return client.connected();
}

bool ClientSecureSync::disconnected() {
    return !client.connected();
}

} // namespace espMqttClientInternals
