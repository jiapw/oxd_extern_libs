#pragma once

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <string_view>

#include "base.h"

#include "http_server.h"
#include "websocket_server.h"

#pragma comment(lib, "libcrypto_d.lib")
#pragma comment(lib, "libssl_d.lib")
#pragma comment(lib, "zlibstatic_d.lib")


namespace websvc {



class Factory
{
public:
    static std::shared_ptr<HttpServer> CreateHttpServer(const HttpServerConfig& config)
    {
        return std::shared_ptr<HttpServer>(new SwsHttpServer(config));
    }

    
    static std::shared_ptr<WebSocketServer> CreateWebSocketServer(const WebSocketServerConfig& config)
    {
        return std::shared_ptr<WebSocketServer>(new SwsWebSocketServer(config));
    }
};




} // namespace websvc
