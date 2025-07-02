#include <simple/log.hpp>
#include <simple/http.hpp>
#include <simple/time.hpp>


#include <cassert>

//const std::string url = "https://cls.2ndu.com/chunk-store/v1/hv?file_id=ab7cb16a9a44d65c0ff524fc7518909f0fd4a3314aecd38ecc53c7a94ff0d4c9";
const std::string url = "https://video1.2ndu.com/16MB/4x4_0.bin";

LOG_DEFINE(HttpTest);

void test_http_sync()
{
	if(1)
	{
		auto r = simple::Http::Sync::Get("https://www.sina.com.cn", 1*50);
		if (r)
			printf("%s\n\n", r->c_str());
	}

	if(1)
	{
		std::string s;
		bool b = simple::Http::Sync::Post(
			"https://echo.free.beeceptor.com", 
			{ 
				{"name_1","value_1"}, 
				{"name_2","file.name","0123456789"},
				{"name_3","callback",[](std::string& buf)->bool{
					buf.resize(1024 * 20);
					//buf = "\0\1\2\3\4\5zbxdefghijklmnopqrstuvwxyz\5\4\3\2\1\0";
					return true;
				}}
			}, 
			s,
			1*100
		);
		if (b)
			printf("%s\n\n", s.c_str());
	}
}

#define BLOCK_READ
void test_http_manager()
{
	
	auto http_mngr = std::make_shared<simple::HttpManager>();
	http_mngr->start_work_thread();

	std::vector<std::string> urls = {
		"http://bing.com",
		"https://video1.2ndu.com/1c596349-d532-41be-b318-b4b2b02c148d/1/-qCuqohLXT2Yp3nXaY6LaTqhINHbIhfFM9YRbinAbpQ%3D.data",
		"https://video1.2ndu.com/1c596349-d532-41be-b318-b4b2b02c148d/1/0YcdSTkZRNY2vqksLgrmMm2jzPN6TgXzyzkQ5n1PbjM%3D.data",
		"https://video1.2ndu.com/1c596349-d532-41be-b318-b4b2b02c148d/1/M7VirI7Ui8H6FrOn8rZdJ6Fx8D65yC8Gm8BU9VuRSzE%3D.data",
		"https://video1.2ndu.com/1c596349-d532-41be-b318-b4b2b02c148d/1/dHRC9JQAonj5B19y1x66_5ux48TgKxFHO_HLckZzZaA%3D.data",
		//"https://code.visualstudio.com/sha/download?build=stable&os=win32-x64-user",
	};

	/*
	http_mngr->create_thread_timer(1000 * 1,
		[self= http_mngr](const boost::system::error_code& ec) {
			self->stop_work_thread();
		});
	*/

	for (auto i =0 ;i<urls.size();i++)
	{
		simple::ms::timestamp tm;

		printf("\nstart: %lld \n", simple::ms::now());
		
		{
			auto  http_req = simple::HttpContext::create(urls[i],
				[i](const simple::HttpContext* ctx, int status_code)->bool
				{
					HttpTest::Info(
						"recv header: {} status code:{} content length:{}",
						ctx->request.url_string(),
						status_code, 
						ctx->response.content_length
					);

					if (i < 4)
						return true;
					else
						return false;
				},

#if defined(BLOCK_READ)
				[i](const simple::HttpContext* ctx, uint64_t offset, std::string_view& slice)->bool
				{
					// todo
					if (i < 2)
						return true;
					else
						return false;
				},
#else
				nullptr,
#endif

				[](const simple::HttpContext* ctx, const simple::error_code& sys_error_code, int http_status_code, const std::string& body)->void
				{
					auto recv_size = body.size() ? body.size() : ctx->response.slice_recv_bytes;
					if (simple::is_http_status_2xx(http_status_code))
					{
						HttpTest::Info(
							"recv body: {} status code:{} content recv:{}",
							ctx->request.url_string(),
							http_status_code,
							recv_size
						);
					}
					else
					{
						HttpTest::Warn(
							"recv body: {} status code:{} content recv:{} RC:{}",
							ctx->request.url_string(),
							http_status_code,
							recv_size,
							sys_error_code.message()
						);
					}
				}

			);
			http_mngr->execute(http_req);

			while (!http_req->is_completed()&& http_mngr->is_working())
			{
				std::this_thread::sleep_for(std::chrono::milliseconds(100));
			}
		}

		printf("stop: %lld \n", simple::ms::now());
		printf("elapsed: %lld \n", tm.elapsed());
	}

	http_mngr->stop_work_thread();

}

void test_http_error_code()
{
	LOG_DEFINE(THEC);

	{
		simple::HttpManager http_mngr;
		http_mngr.start_work_thread();
		{
			auto http_req = simple::HttpContext::create(
				"http://www.baidu.com",
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


void test_http_async()
{
	LOG_DEFINE(ASYNC);

	std::vector<std::string> urls = {
		"http://bing.com",
		"https://video1.2ndu.com/1c596349-d532-41be-b318-b4b2b02c148d/1/-qCuqohLXT2Yp3nXaY6LaTqhINHbIhfFM9YRbinAbpQ%3D.data",
		"https://video1.2ndu.com/1c596349-d532-41be-b318-b4b2b02c148d/1/0YcdSTkZRNY2vqksLgrmMm2jzPN6TgXzyzkQ5n1PbjM%3D.data",
		"https://video1.2ndu.com/1c596349-d532-41be-b318-b4b2b02c148d/1/M7VirI7Ui8H6FrOn8rZdJ6Fx8D65yC8Gm8BU9VuRSzE%3D.data",
		"https://video1.2ndu.com/1c596349-d532-41be-b318-b4b2b02c148d/1/dHRC9JQAonj5B19y1x66_5ux48TgKxFHO_HLckZzZaA%3D.data",
		//"https://code.visualstudio.com/sha/download?build=stable&os=win32-x64-user",
	};

	std::vector<std::shared_ptr<simple::HttpContext>> ctxes;

	for (auto i = 0; i < urls.size(); i++)
	{
		ASYNC::Info("start: {}", urls[i]);

		auto ctx = simple::Http::Async::Get(
			urls[i],
			[](simple::HttpContext* ctx, const simple::error_code& sys_error_code, int http_status_code, const std::string& body)
			{
				ASYNC::Info("finish: {}, sys:{}, http:{}, length:{}", ctx->request.url_string(), sys_error_code.value(), http_status_code, body.size());
			});

		ctxes.emplace_back(ctx);
	}

	simple::ms::sleep(1 * 1000);

	for (auto i = 0; i < ctxes.size(); i++)
	{
		auto ctx = ctxes[i];
		if (!ctx->status.completed)
		{
			ASYNC::Warn("cancel: {}", ctx->request.url_string());
			ctx->Cancel();
		}
			
	}

}

int main()
{
	simple::test_logger();

	//test_http_error_code();

	//test_http_sync();

	test_http_async();

	simple::ms::sleep(1 * 1000);

	return 0;
}
