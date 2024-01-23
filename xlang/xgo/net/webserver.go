package net

/*
//////////////////////////////////////////////////////////////////////////////////////////////
// Everything in comments above the import "C" is C code and will be compiles with the GCC. //
//////////////////////////////////////////////////////////////////////////////////////////////

#include "abi.h"

xgo_function_entry _funcs = {NULL};

inline static xgo_http_response* call_http_handler(xgo_http_request* request, xgo_slice* blob, int64_t count)
{
	return _funcs.http_handler ? _funcs.http_handler(request, blob, count) : NULL;
}

inline static bool call_http_response_free(xgo_http_response* response)
{
	return _funcs.http_response_free ? _funcs.http_response_free(response) : false;
}

inline static xgo_ws_message* call_ws_message_handler(xgo_ws_message* msg)
{
	return _funcs.ws_message_handler ? _funcs.ws_message_handler(msg) : NULL;
}

inline static xgo_ws_message* call_ws_event_handler(xgo_ws_message* msg)
{
	return _funcs.ws_event_handler ? _funcs.ws_event_handler(msg) : NULL;
}

inline static bool call_ws_message_free(xgo_ws_message* msg)
{
	return _funcs.ws_message_free ? _funcs.ws_message_free(msg) : false;
}

*/
import "C"

import (
	"io"
	"net/http"
	"runtime"
	"unsafe"
)

var (
	http_server *http.Server
)

func onHttpRequest(w http.ResponseWriter, r *http.Request) {

	s, err := MarshalHttpRequest(r)

	if err == nil {

		var (
			c_request C.xgo_http_request
			pinner    runtime.Pinner
		)

		c_request.desc.len = (C.int64_t)(len(s))
		c_request.desc.str = (*C.char)(unsafe.Pointer(&s[0]))

		pinner.Pin(c_request.desc.str)
		response := C.call_http_handler((*C.xgo_http_request)(unsafe.Pointer(&c_request)), nil, 0)
		pinner.Unpin()

		if response != nil {
			var s = C.GoString((*C.char)(unsafe.Pointer(response.desc.str)))
			io.WriteString(w, s)
			C.call_http_response_free(response)
		}
	}
	io.WriteString(w, "Default Content\n")
}

func StartWebServer(config string) {

	// todo : config json
	http_server = &http.Server{Addr: config, Handler: nil}

	http.HandleFunc("/", onHttpRequest)

	go func(args string) {
		http_server.ListenAndServe()
	}(config)
}

func StopWebServer() {
	http_server.Close()
	http_server = nil
}
