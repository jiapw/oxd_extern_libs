#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <system_error>

#include "base.h"

namespace websvc {

class WebSocketConnection {
public:
    virtual Result Send(const std::string& message) = 0;
};

using WebSocketMessageHandler = std::function<void(WebSocketConnection&, const std::string&)>;
using WebSocketOpenHandler = std::function<void(WebSocketConnection&)>;
using WebSocketCloseHandler = std::function<void(WebSocketConnection&, int, const std::string&)>;
using WebSocketErrorHandler = std::function<void(WebSocketConnection&, const std::error_code&)>;
using WebSocketPingHandler = std::function<void(WebSocketConnection&)>;
using WebSocketPongHandler = std::function<void(WebSocketConnection&)>;

class WebSocketEndpoint {
public:
    void OnMessage(WebSocketConnection& connection, const std::string& in_message) const;
    void OnOpen(WebSocketConnection& connection) const;
    void OnClose(WebSocketConnection& connection, int status_code, const std::string& reason) const;
    void OnError(WebSocketConnection& connection, const std::error_code& error_code) const;
    void OnPing(WebSocketConnection& connection) const;
    void OnPong(WebSocketConnection& connection) const;

public:
    const std::optional<WebSocketMessageHandler>& message_handler() const { return message_handler_; }
    void set_message_handler(const WebSocketMessageHandler& message_handler) { message_handler_ = message_handler; }

    const std::optional<WebSocketOpenHandler>& open_handler() const { return open_handler_; }
    void set_open_handler(const WebSocketOpenHandler& open_handler) { open_handler_ = open_handler; }

    const std::optional<WebSocketCloseHandler>& close_handler() const { return close_handler_; }
    void set_close_handler(const WebSocketCloseHandler& close_handler) { close_handler_ = close_handler; }

    const std::optional<WebSocketErrorHandler>& error_handler() const { return error_handler_; }
    void set_error_handler(const WebSocketErrorHandler& error_handler) { error_handler_ = error_handler; }

    const std::optional<WebSocketPingHandler>& ping_handler() const { return ping_handler_; }
    void set_ping_handler(const WebSocketPingHandler& ping_handler) { ping_handler_ = ping_handler; }

    const std::optional<WebSocketPingHandler>& pong_handler() const { return pong_handler_; }
    void set_pong_handler(const WebSocketPongHandler& pong_handler) { pong_handler_ = pong_handler; }

private:
    std::optional<WebSocketMessageHandler> message_handler_;
    std::optional<WebSocketOpenHandler> open_handler_;
    std::optional<WebSocketCloseHandler> close_handler_;
    std::optional<WebSocketErrorHandler> error_handler_;
    std::optional<WebSocketPingHandler> ping_handler_;
    std::optional<WebSocketPingHandler> pong_handler_;
    // TODO: add interface for handshake.
};

using WebSocketServerStartCallback = std::function<void(unsigned short /*port*/)>;

class WebSocketServer {
public:
    virtual Result RegisteEndpoint(const std::string& path, std::shared_ptr<WebSocketEndpoint> endpoint) = 0;
    virtual Result Start(const WebSocketServerStartCallback& callback = nullptr) = 0;
    virtual Result Stop() = 0;
};

struct WebSocketServerConfig {
    uint16_t port;
    size_t thread_pool_size;
};

std::shared_ptr<WebSocketServer> CreateWebSocketServer(const WebSocketServerConfig& config);

} // namespace websvc
