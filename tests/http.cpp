#include <simple/http.hpp>
#include <simple/time.hpp>

#include <cassert>

const std::string url = "https://cls.2ndu.com/chunk-store/v1/hv?file_id=ab7cb16a9a44d65c0ff524fc7518909f0fd4a3314aecd38ecc53c7a94ff0d4c9";

void test_http_tools()
{
	if(0)
	{
		auto r = simple::http_tools::sync_http_get("https://www.sina.com.cn");
		assert(r);
		printf("%s\n\n", r->c_str());
	}

	{
		std::string r;
		simple::http_tools::sync_http_post(
			"https://echo.free.beeceptor.com", 
			{ 
				{"name_1","value_1"}, 
				{"name_2","file.name","0123456789"},
				{"name_3","callback",[](std::string& buf)->void{
					buf = "\0\1\2\3\4\5zbxdefghijklmnopqrstuvwxyz\5\4\3\2\1\0";
				}}
			}, 
			r
		);
		printf("%s\n\n", r.c_str());
	}
}

void test_http_manager()
{
	simple::nanoseconds::timestamp tm;
	printf("start: %lld \n", simple::ms::now());
	simple::seconds::sleep(10);
	{
		simple::http_manager http_mngr;
		http_mngr.start_work_thread();
		{
			auto  http_req = std::make_shared<simple::http_context>(url,
				[](const simple::http_context* ctx, int status_code)->void
				{
					printf("recv header:\n status code:%d \n content length:%lld \n", status_code, ctx->response.content_length);
				},

#if defined(BLOCK_READ)
				[](const simple::http_context* ctx, uint64_t offset, std::string_view& slice)->void
				{
					printf("recv block: offset: %lld, size:%lld \n", offset, slice.size());
				},
#else
				nullptr,
#endif

				[](const simple::http_context* ctx, int status_code, const std::string& body)->void
				{
					printf("http finish:\n status code:%d, total size:%lld \n", status_code, ctx->response.content_length);
				}

			);
			http_mngr.execute(http_req);

			while (!http_req->finished)
			{
				std::this_thread::sleep_for(std::chrono::milliseconds(100));
			}
		}
		http_mngr.stop_work_thread();
	}
	printf("stop: %lld \n", simple::ms::now());
	printf("elapsed: %lld \n", tm.elapsed());

}


int main()
{
	test_http_tools();
	//test_http_manager();

	return 0;
}
