#include <simple/log.hpp>
#include <simple/http.hpp>
#include <simple/time.hpp>


#include <cassert>

//const std::string url = "https://cls.2ndu.com/chunk-store/v1/hv?file_id=ab7cb16a9a44d65c0ff524fc7518909f0fd4a3314aecd38ecc53c7a94ff0d4c9";
const std::string url = "https://video1.2ndu.com/16MB/4x4_0.bin";

void test_http_tools()
{
	if(1)
	{
		auto r = simple::Http::Sync::Get("https://www.sina.com.cn", 10*1000);
		assert(r);
		printf("%s\n\n", r->c_str());
	}

	{
		std::string r;
		simple::Http::Sync::Post(
			"https://echo.free.beeceptor.com", 
			{ 
				{"name_1","value_1"}, 
				{"name_2","file.name","0123456789"},
				{"name_3","callback",[](std::string& buf)->bool{
					buf = "\0\1\2\3\4\5zbxdefghijklmnopqrstuvwxyz\5\4\3\2\1\0";
					return true;
				}}
			}, 
			r,
			10*1000
		);
		printf("%s\n\n", r.c_str());
	}
}

void test_http_manager()
{
	
	simple::HttpManager http_mngr;
	http_mngr.start_work_thread();

	std::vector<std::string> urls = {
		"https://video1.21ndu.com/16MB/4x4_0.bin",
		"https://video1.2ndu.com/16MB/4x4_1.bin",
		"https://video1.2ndu.com/16MB/4x4_4.bin",
		"https://video1.2ndu.com/16MB/4x4_2.bin"
	};

	for (auto i =0 ;i<4;i++)
	{
		simple::ms::timestamp tm;

		printf("\nstart: %lld \n", simple::ms::now());
		
		{
			auto  http_req = simple::HttpContext::create(urls[i],
				[](const simple::HttpContext* ctx, int status_code)->void
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

				[](const simple::HttpContext* ctx, const simple::error_code& sys_error_code, int http_status_code, const std::string& body)->void
				{
					assert(simple::is_http_status_2xx(http_status_code));
					printf("http finish:\n status code:%d, total size:%lld \n", http_status_code, ctx->response.content_length);
				}

			);
			http_mngr.execute(http_req);

			while (!http_req->is_completed())
			{
				std::this_thread::sleep_for(std::chrono::milliseconds(100));
			}
		}

		printf("stop: %lld \n", simple::ms::now());
		printf("elapsed: %lld \n", tm.elapsed());
	}

	http_mngr.stop_work_thread();

}

void test_http_error_code()
{
	LOG_DEFINE(THEC);

	{
		simple::HttpManager http_mngr;
		http_mngr.start_work_thread();
		{
			auto http_req = simple::HttpContext::create(
				"http://bing.com",
				nullptr,
				nullptr,
				[](simple::HttpContext* ctx, const simple::error_code& sys_error_code, int http_status_code, const std::string& body) 
				{
					THEC::Info("http error code:{}", http_status_code);
				}
			);
			http_req->config.resolve_timeout = 1;
			http_mngr.execute(http_req);
			while (!http_req->is_completed())
			{
				std::this_thread::sleep_for(std::chrono::milliseconds(100));
			}
			THEC::Info("http error code:{}", http_req->status.sys_error_code.to_string());
		}
		http_mngr.stop_work_thread();
		
	}

}

int main()
{
	//simple::test_logger()
	test_http_error_code();
	//test_http_tools();
	//test_http_manager();

	return 0;
}
