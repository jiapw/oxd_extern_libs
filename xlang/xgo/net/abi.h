#pragma once

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

extern xgo_function_entry _funcs;