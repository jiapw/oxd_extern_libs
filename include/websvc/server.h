#pragma once

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <string_view>

#include "base.h"

#include "http_server.h"
//#include "server_websocket.h"

namespace websvc {



class Factory
{
public:
    static std::shared_ptr<HttpServer> CreateHttpServer(const HttpServerConfig& config)
    {
        return std::shared_ptr<HttpServer>(new SwsHttpServer(config));
    }

    /*
    static std::shared_ptr<WebSocketServer> CreateWebSocketServer(const WebSocketServerConfig& config)
    {

    }
    */
};




} // namespace websvc
