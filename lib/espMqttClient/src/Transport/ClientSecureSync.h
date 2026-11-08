/*
Copyright (c) 2022 Bert Melis. All rights reserved.

This work is licensed under the terms of the MIT license.  
For a copy, see <https://opensource.org/licenses/MIT> or
the LICENSE file.
*/

#pragma once


// #include "esp_tls.h"
#include <WiFiClient.h>
#include <ESP_SSLClient.h>
#include "Transport.h"

namespace espMqttClientInternals {

// what happened during the last connect(), for logging
// ESP_SSLClient frees its BearSSL engine as soon as a handshake fails, so the BearSSL error code is not available
struct ConnectDiag {
    enum class Stage : uint8_t { NONE, DNS, TCP, TLS, OK };
    Stage     stage      = Stage::NONE; // the stage that failed, or OK
    IPAddress ip;                       // address the host name resolved to
    int       sock_errno = 0;           // errno from a failed TCP connect
    uint32_t  dns_ms     = 0;
    uint32_t  tcp_ms     = 0;
    uint32_t  tls_ms     = 0;
    bool      mfln       = false; // TLS max fragment length negotiated with the broker
    uint16_t  rx_buffer  = 0;     // TLS receive buffer size in bytes
};

class ClientSecureSync : public Transport {
  public:
    ClientSecureSync();
    ~ClientSecureSync();
    bool   connect(IPAddress ip, uint16_t port) override;
    bool   connect(const char * host, uint16_t port) override;
    size_t write(const uint8_t * buf, size_t size) override;
    int    read(uint8_t * buf, size_t size) override;
    void   stop() override;
    bool   connected() override;
    bool   disconnected() override;

    WiFiClient    basic_client;
    ESP_SSLClient client;
    ConnectDiag   diag;

  private:
    bool connectStages(const char * host, IPAddress ip, uint16_t port);
    uint16_t _rxBufferSize;
};

} // namespace espMqttClientInternals
