package main

/*
//////////////////////////////////////////////////////////////////////////////////////////////
// Everything in comments above the import "C" is C code and will be compiles with the GCC. //
//////////////////////////////////////////////////////////////////////////////////////////////

#include "../net/abi.h"
*/
import "C"

import (
	net "xgo/net"
)

func main() {

	net.StartWebServer("127.0.0.1:3333")

	select {}
}

//export api_set_callback_function
func api_set_callback_function(_entry *C.xgo_function_entry) {
	C._funcs = *_entry
}

//export api_start_web_server
func api_start_web_server(_config *C.char) {
	net.StartWebServer(C.GoString(_config))
}

//export api_stop_web_server
func api_stop_web_server() {
	net.StopWebServer()
}
