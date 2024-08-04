#include <simple/http.hpp>
#include <simple/json.hpp>
#include <simple/time.hpp>

#include <thread>
#include <chrono>
#include <boost/asio.hpp>
#include <boost/asio/strand.hpp>

#include <cassert>

boost::asio::io_context m_ioc;
boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work_guard = boost::asio::make_work_guard(m_ioc);
boost::asio::io_context::strand m_strand(m_ioc);

int n = 0;

void do_sth(int i)
{
	std::this_thread::sleep_for(std::chrono::milliseconds(10));
	int t = n;
	n = t + 1;
	printf("%d\n", i);
}

void strand_do_sth(int i)
{
	m_ioc.post([i]() {
		do_sth(i); 
	});
}

int main_strand()
{
	std::thread([]() {
		printf("run() start\n");
		m_ioc.run();
		printf("run() stop\n");
	}).detach();


	for (int i = 0; i < 10; i++)
	{
		std::thread(strand_do_sth, i).detach();
	}

	std::this_thread::sleep_for(std::chrono::milliseconds(1000));

	printf("\n%d\n", n);

	work_guard.reset();

	return 0;
}

int main_multi_thread()
{

	for (int i = 0; i < 10; i++)
	{
		std::thread(do_sth, i).detach();
	}

	std::thread([]() {
		m_ioc.run();
		}).detach();

	std::this_thread::sleep_for(std::chrono::milliseconds(10000));

	printf("\n%d\n", n);

	return 0;
}

int main_t()
{
	//return main_multi_thread();

	return main_strand();
}


int main()
{
	//std::string res;
	//simple::http::get("www.baidu.com", "443", "/", "1.1", res);
	/*
	auto  http_req_1 = std::make_shared<simple::http_request>("http://www.baidu.com");
	auto  http_req_2 = std::make_shared<simple::http_request>("http://wiremin.org");


	simple::http_manager http_mngr;

	http_mngr.start_work_thread();
	std::this_thread::sleep_for(std::chrono::milliseconds(500));

	http_mngr.execute(http_req_1);
	http_mngr.execute(http_req_2);

	while (!http_req_1->ended || !http_req_2->ended)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}

	http_req_1 = nullptr;
	http_req_2 = nullptr;

	http_mngr.stop_work_thread();
	*/

	//for (;;)
		//simple::http_tools::sync_http_get("https://dldir1v6.qq.com/weixin/Windows/WeChatSetup.exe", res);

	//simple::sync_http_get("https://www.baidu.com", res);

	std::string url = "https://cls.2ndu.com/chunk-store/v1/hv?file_id=ab7cb16a9a44d65c0ff524fc7518909f0fd4a3314aecd38ecc53c7a94ff0d4c9";

	if (0)
	{
		auto r = simple::http_tools::sync_http_get(url);
		assert(r);
	}

	if (0)
	{
		auto r = simple::http_tools::sync_http_get(url, (void*)(1));
		assert(r);
	}

#define BLOCK_READ

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
				[](const simple::http_context* ctx, uint64_t offset, std::string_view& block)->void
				{
					//printf("recv block: offset: %lld, size:%lld \n", offset, block.size());
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
	return 0;
}
