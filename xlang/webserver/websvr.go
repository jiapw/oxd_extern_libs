package main

/*
////////////////////////////////////////////////////////////////////////////////////////////
// Everything in comments above the import "C" is C code and will be compiles with the GCC. //
//////////////////////////////////////////////////////////////////////////////////////////////

#include<stdint.h>
#include<stdbool.h>

typedef struct
{
	uint8_t*	array;
	int64_t		len;
}
xgo_slice;

typedef struct
{
	char*		str;
	int64_t		len;
}
xgo_string;

typedef struct
{
	xgo_string	desc;	// json include "method", "path", "version", "headers", "customize fields", ....
}
xgo_http_request;

typedef struct
{
	xgo_string	desc;	// json include "version", "status code", "status message", "headers", "custom fields", ....
	xgo_slice	body;	// "response body"
}
xgo_http_response;

typedef struct
{
	xgo_string	desc;	// json include "message type", "topic"
	xgo_slice	data;	// binaray data (set simple text data in desc)
}
xgo_ws_message;


typedef	xgo_http_response*	(*xgo_ptr_http_handler)			(xgo_http_request* request, xgo_slice* blob, int64_t count);
typedef	bool 				(*xgo_ptr_http_response_free)	(xgo_http_response* response);

typedef xgo_ws_message*		(*xgo_ptr_ws_message_handler)	(xgo_ws_message* msg);
typedef xgo_ws_message*		(*xgo_ptr_ws_event_handler)		(xgo_ws_message* event);	// std: "Ping" "Pong" "Close", customize: "_Connect"
typedef	bool 				(*xgo_ptr_ws_message_free) 		(xgo_ws_message* msg);

typedef struct
{
	xgo_ptr_http_handler		http_handler;
	xgo_ptr_http_response_free	http_response_free;
	xgo_ptr_ws_message_handler	ws_message_handler;
	xgo_ptr_ws_event_handler	ws_event_handler;
	xgo_ptr_ws_message_free		ws_message_free;
}
xgo_function_entry;

inline static xgo_http_response* call_http_handler(xgo_ptr_http_handler f, xgo_http_request* request, xgo_slice* blob, int64_t count)
{
	return f ? f(request, blob, count) : NULL;
}

inline static bool call_http_response_free(xgo_ptr_http_response_free f, xgo_http_response* response)
{
	return f ? f(response) : false;
}

inline static xgo_ws_message* call_ws_message_handler(xgo_ptr_ws_message_handler f, xgo_ws_message* msg)
{
	return f ? f(msg) : NULL;
}

inline static xgo_ws_message* call_ws_event_handler(xgo_ptr_ws_event_handler f, xgo_ws_message* msg)
{
	return f ? f(msg) : NULL;
}

inline static bool call_ws_message_free(xgo_ptr_ws_message_free f, xgo_ws_message* msg)
{
	return f ? f(msg) : false;
}


*/
import "C"

import (
	"encoding/json"
	"io"
	"net/http"
	"runtime"
	"unsafe"
)

var (
	c_xgo_function_entry C.xgo_function_entry
	http_server          *http.Server
)

func json_Marshal_http_Request(r *http.Request) ([]byte, error) {
	j, err := json.Marshal(struct {
		Host       string
		Method     string
		Path       string
		Proto      string
		RemoteAddr string
	}{
		Host:       r.Host,
		Method:     r.Method,
		Path:       r.URL.Path,
		Proto:      r.Proto,
		RemoteAddr: r.RemoteAddr,
	})
	if err != nil {
		return nil, err
	}
	return j, nil
}

func onHttpRequest(w http.ResponseWriter, r *http.Request) {

	s, err := json_Marshal_http_Request(r)

	if err == nil {

		var (
			c_request C.xgo_http_request
			pinner    runtime.Pinner
		)

		c_request.desc.len = (C.int64_t)(len(s))
		c_request.desc.str = (*C.char)(unsafe.Pointer(&s[0]))

		pinner.Pin(c_request.desc.str)
		response := C.call_http_handler(c_xgo_function_entry.http_handler, (*C.xgo_http_request)(unsafe.Pointer(&c_request)), nil, 0)
		pinner.Unpin()

		if response != nil {
			var s = C.GoString((*C.char)(unsafe.Pointer(response.desc.str)))
			io.WriteString(w, s)
			C.call_http_response_free(c_xgo_function_entry.http_response_free, response)
		}
	}
	io.WriteString(w, "Default Content\n")
}

func main() {

	start_web_server("127.0.0.1:3333")

	select {}
}

func start_web_server(config string) {

	// todo : config json
	http_server = &http.Server{Addr: config, Handler: nil}

	http.HandleFunc("/", onHttpRequest)

	go func(args string) {
		http_server.ListenAndServe()
	}(config)
}

func stop_web_server() {
	http_server.Close()
	http_server = nil
}

//export api_set_callback_function
func api_set_callback_function(_entry *C.xgo_function_entry) {
	c_xgo_function_entry = *_entry
}

//export api_start_web_server
func api_start_web_server(_config *C.char) {
	start_web_server(C.GoString(_config))
}

//export api_stop_web_server
func api_stop_web_server() {
	stop_web_server()
}
