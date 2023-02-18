#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <system_error>

#include "base.h"

#include "simple-web-server/server_wss.hpp"

namespace websvc {

class SwsWebSocketServerConnection : public WebSocketConnection {
public:
    using server_impl_type = SimpleWeb::SocketServer<SimpleWeb::WSS>;
    using connection_impl_type = server_impl_type::Connection;

public:
    Result Send(const std::string& message) override
    {
        connection_->send(message);
        return Result::SS_OK;
    }

public:
    explicit SwsWebSocketServerConnection(std::shared_ptr<connection_impl_type> connection)
        : connection_(connection)
    {
    }
    ~SwsWebSocketServerConnection() = default;

private:
    std::shared_ptr<connection_impl_type> connection_;
};

class SwsWebSocketServer : public WebSocketServer {
public:
    using server_impl_type = SimpleWeb::SocketServer<SimpleWeb::WSS>;
    using connection_impl_type = server_impl_type::Connection;
    using in_message_impl_type = server_impl_type::InMessage;
    using endpoint_impl_type = server_impl_type::Endpoint;

public:
    Result RegisteEndpoint(const std::string& path, std::shared_ptr<WebSocketEndpoint> endpoint) override
    {
        if (!endpoint)
            return Result::ERR_FAIL;

        endpoint_impl_type& endpoint_impl = server_ptr_->endpoint[path];

        endpoint_impl.on_message = [endpoint](std::shared_ptr<connection_impl_type> connection_impl, std::shared_ptr<in_message_impl_type> in_message_impl) {
            std::string in_message_string = in_message_impl->string();

            SwsWebSocketServerConnection connection(connection_impl);
            std::string in_message = in_message_impl->string();
            endpoint->OnMessage(connection, in_message);
        };

        endpoint_impl.on_open = [endpoint](std::shared_ptr<connection_impl_type> connection_impl) {
            SwsWebSocketServerConnection connection(connection_impl);
            endpoint->OnOpen(connection);
        };

        endpoint_impl.on_close = [endpoint](std::shared_ptr<connection_impl_type> connection_impl, int status_code, const std::string& reason) {
            SwsWebSocketServerConnection connection(connection_impl);
            endpoint->OnClose(connection, status_code, reason);
        };

        endpoint_impl.on_error = [endpoint](std::shared_ptr<connection_impl_type> connection_impl, const std::error_code& error_code) {
            SwsWebSocketServerConnection connection(connection_impl);
            endpoint->OnError(connection, error_code);
        };

        endpoint_impl.on_ping = [endpoint](std::shared_ptr<connection_impl_type> connection_impl) {
            SwsWebSocketServerConnection connection(connection_impl);
            endpoint->OnPing(connection);
        };

        endpoint_impl.on_pong = [endpoint](std::shared_ptr<connection_impl_type> connection_impl) {
            SwsWebSocketServerConnection connection(connection_impl);
            endpoint->OnPong(connection);
        };

        return Result::SS_OK;
    }

    Result Start(const WebSocketServerStartCallback& callback = nullptr) override
    {
        server_ptr_->start(callback);
        return Result::SS_OK;
    }

    Result Stop() override
    {
        server_ptr_->stop();
        return Result::SS_OK;
    }

public:
    explicit SwsWebSocketServer(const WebSocketServerConfig& config)
        : server_ptr_(nullptr)
    {
        CertSuit cst;
        auto r = GenerateCertificatePrivateKeyPair(cst);
        asio::const_buffer cert(cst.certificate.c_str(), cst.certificate.size());
        asio::const_buffer pkey(cst.private_key.c_str(), cst.private_key.size());
        server_ptr_ = std::make_shared<server_impl_type>(cert, pkey);

        server_ptr_->config.port = config.port;
        server_ptr_->config.thread_pool_size = config.thread_pool_size;
    }

    ~SwsWebSocketServer() = default;

private:
    std::shared_ptr<server_impl_type> server_ptr_;
};


} // namespace websvc
