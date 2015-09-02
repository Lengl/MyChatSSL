#include <algorithm>
#include <cstdlib>
#include <deque>
#include <iostream>
#include <list>
#include <set>
#include <boost\asio.hpp>
#include <boost\asio\ssl.hpp>
#include <boost\bind.hpp>
#include <boost\enable_shared_from_this.hpp>
#include <boost\shared_ptr.hpp>
#include "..\chat_message.h"

typedef std::deque<ChatMessage> chatMessageQueue;
typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> sslSocket;

namespace asio = boost::asio;
namespace ssl = asio::ssl;

class ChatParticipant {
public:
	virtual ~ChatParticipant() {}
	virtual void deliver(const ChatMessage& msg) = 0;
	virtual char* name() {}
	enum { maxNameLength = 20 };
};

typedef boost::shared_ptr<ChatParticipant> chatPartPtr;

//------------------------------------------------------------------

class ChatRoom {
public:
	//Returns "true" if there already is a participant with this name OR if name is too large
	bool checkSameName(char* name) {
		bool res = false;
		if (strlen(name) > ChatParticipant::maxNameLength)
			return true;
		std::for_each(participants.begin(), participants.end(), boost::bind(
			&ChatRoom::cmpName, this, _1, name, res));
		return res;
	}

	void join(chatPartPtr participant) {
		participants.insert(participant);
		std::for_each(recentMessages.begin(), recentMessages.end(), boost::bind(
			&ChatParticipant::deliver,
			participant,
			_1));
		//TODO:Add notification about succecful join
	}

	void leave(chatPartPtr participant) {
		participants.erase(participant);
	}

	void deliver(const ChatMessage& msg) {
		recentMessages.push_back(msg);
		while (recentMessages.size() > maxRecentMsgs)
			recentMessages.pop_front();

		std::for_each(participants.begin(), participants.end(), boost::bind(
			&ChatParticipant::deliver, _1, boost::ref(msg)));
	}

private:
	void cmpName(chatPartPtr participant, char* name, bool &res) {
		res |= (strcmp(participant->name(), name) == 0);
	}

	std::set<chatPartPtr> participants;
	enum { maxRecentMsgs = 100 };
	chatMessageQueue recentMessages;
};

//------------------------------------------------------------------

class session
	: public ChatParticipant,
	public boost::enable_shared_from_this<session> {
public:
	session(
		asio::io_service &io_service,
		ssl::context &context,
		ChatRoom& roomG
		) : socket_(io_service, context),
		room(roomG) {
	}

	//Непонятно: что есть "нижний уровень"?
	sslSocket::lowest_layer_type& socket() {
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
			asio::async_read(
				socket_,
				asio::buffer(readMsg.data(), ChatMessage::headerLength),
				boost::bind(
					&session::handle_read_header,
					//TODO:Выяснить, что же конкретно делает shared from this и как оно работает
					shared_from_this(),
					asio::placeholders::error
					));
		}
		else {
			delete this;
		}
	}

	void handle_read_header(
		const boost::system::error_code& error) {
		if (!error && readMsg.decode_header()) {
			asio::async_read(
				socket_,
				asio::buffer(readMsg.body(), readMsg.body_length()),
				boost::bind(
					&session::handle_read_body,
					this,
					asio::placeholders::error));
		}
		else {
			room.leave(shared_from_this());
			delete this;
		}
	}

	void handle_read_body(
		const boost::system::error_code& error) {
		if (!error) {
			room.deliver(readMsg);
			asio::async_read(
				socket_,
				asio::buffer(readMsg.data(), ChatMessage::headerLength),
				boost::bind(&session::handle_read_header, shared_from_this(), asio::placeholders::error));
		}
		else {
			room.leave(shared_from_this());
			delete this;
		}
	}

	void deliver(const ChatMessage& msg) {
		//Шайтан-система: Т.к. происходит асинхронная запись, то записывает он (практически) всё сразу, и "буфер пуст" === кольцо handle_write уже было запущено. А если не было - так запустим.
		bool writeInProgress = !writeMsgs.empty();
		writeMsgs.push_back(msg);
		if (!writeInProgress) {
			asio::async_write(
				socket_,
				asio::buffer(writeMsgs.front().data(), writeMsgs.front().length()),
				boost::bind(&session::handle_write, shared_from_this(), asio::placeholders::error));
		}
	}

	void handle_write(const boost::system::error_code& error) {
		if (!error) {
			writeMsgs.pop_front();
			if (!writeMsgs.empty()) {
				asio::async_write(
					socket_,
					asio::buffer(writeMsgs.front().data(), writeMsgs.front().length()),
					boost::bind(&session::handle_write, shared_from_this(), asio::placeholders::error));
			}
		}
		else {
			room.leave(shared_from_this());
			delete this;
		}
	}
private:
	sslSocket socket_;
	ChatRoom& room;
	ChatMessage readMsg;
	chatMessageQueue writeMsgs;
	enum { maxLength = 1024 };
	char dataArr[maxLength];
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
		session* new_session = new session(io_service_, context_, room);
		acceptor_.async_accept(
			new_session->socket(),
			boost::bind(
				&server::handle_accept,
				this,
				new_session,
				boost::asio::placeholders::error));
	}

	void handle_accept(session* newSession, const boost::system::error_code& error) {
		if (!error) {
			newSession->start();
		}
		else {
			delete newSession;
		}

		start_accept();
	}

private:
	asio::io_service& io_service_;
	asio::ip::tcp::acceptor acceptor_;
	ssl::context context_;
	ChatRoom room;
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
	}
	catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << "\n";
	}
	return 0;
}