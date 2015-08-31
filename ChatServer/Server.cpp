#include "..\chat_message.h"

#include <iostream>
#include <boost\enable_shared_from_this.hpp>
#include <set>
#include <boost\asio.hpp>
#include <boost\bind.hpp>
#include <boost\asio\ssl.hpp>

//В целом непонятно: Зачем нужны placeholders? Они каким-то образом заменяют exceptions при обработке ошибок, но как?
//А вообще похоже, что так затребовано в boost - через error'ы возвращается результат операции?.

typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket;
namespace asio = boost::asio;
namespace ssl = asio::ssl;

class session {
public:
	session(
		asio::io_service &io_service,
		ssl::context &context
		) : socket_(io_service, context) {
	}

	//Непонятно: что есть "нижний уровень"?
	ssl_socket::lowest_layer_type& socket() {
		return socket_.lowest_layer();
	}

	void start() {
		socket_.async_handshake(
			ssl::stream_base::server,
			boost::bind(
				&session::handle_handshake,
				this,
				asio::placeholders::error));
	}

	void handle_handshake(const boost::system::error_code& error) {
		if (!error) {
			socket_.async_read_some(
				asio::buffer(data_, max_length),
				boost::bind(
					&session::handle_read,
					this,
					asio::placeholders::error,
					asio::placeholders::bytes_transferred
					));
		}
		else {
			delete this;
		}
	}

	void handle_read(
		const boost::system::error_code& error,
		size_t bytes_transferred) {
		if (!error) {
			asio::async_write(
				socket_,
				asio::buffer(data_, bytes_transferred),
				boost::bind(
					&session::handle_write,
					this,
					asio::placeholders::error));
		}
		else {
			delete this;
		}
	}

	void handle_write(const boost::system::error_code& error) {
		if (!error) {
			socket_.async_read_some(
				asio::buffer(data_, max_length),
				boost::bind(
					&session::handle_read,
					this,
					asio::placeholders::error,
					asio::placeholders::bytes_transferred));
		}
		else {
			delete this;
		}
	}
private:
	ssl_socket socket_;
	enum {max_length = 1024};
	char data_[max_length];
};

class server {
public:
	server(asio::io_service &io_service, unsigned short port)
		: 
		io_service_(io_service),
		acceptor_(
			io_service,
			asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port)
			),
		context_(ssl::context::sslv23) 
	{
		context_.set_options(
			ssl::context::default_workarounds
			| ssl::context::no_sslv2
			//Непонятно: что это значит и зачем?
			| ssl::context::single_dh_use);
		context_.set_password_callback(boost::bind(&server::getPaswd, this));
		context_.use_certificate_chain_file("server.crt");
		//Непонятно: почему используется именно формат PEM, чем отличается от других, есть ли круче
		context_.use_private_key_file("server.key", ssl::context::pem);
		context_.use_tmp_dh_file("dh512.pem");

		start_accept();
	}
	//Непонятно: Не опасно ли этот пароль хранить в таком явном виде? И что это за пароль?
	std::string getPaswd() const {
		return "test";
	}

	void start_accept() {
		session* new_session = new session(io_service_, context_);
		acceptor_.async_accept(
			new_session->socket(),
			boost::bind(
				&server::handle_accept,
				this,
				new_session,
				boost::asio::placeholders::error));
	}

	void handle_accept(session* new_session, const boost::system::error_code& error) {
		if (!error) {
			new_session->start();
		}
		else {
			delete new_session;
		}

		start_accept();
	}

private:
	asio::io_service& io_service_;
	asio::ip::tcp::acceptor acceptor_;
	ssl::context context_;
};

int main(int argc, char* argv[]) {
	try {
		if (argc != 2) {
			std::cerr << "Takes only one argument: <port>\n";
			return 1;
		}
		asio::io_service io_service;
		//server s(io_service, std::atoi(argv[1]));
		io_service.run();
	} catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << "\n";
	}
	return 0;
}