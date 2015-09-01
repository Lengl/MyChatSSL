#pragma once
#include <cstdio>
#include <cstdlib>
#include <cstring>

class ChatMessage {
public:
	//unnamed enum - when you need fields without declaring a variable?
	//some kind of replacement of static & const?
	enum { headerLength = 4 };
	enum { maxBodyLength = 512 };

	ChatMessage() : bodyLength(0) {
	}

	const char* data() const {
		return dataArr;
	}

	char* data() {
		return dataArr;
	}

	size_t length() const {
		return headerLength + bodyLength;
	}

	const char* body() const {
		return dataArr + headerLength;
	}

	char* body() {
		return dataArr + headerLength;
	}

	size_t body_length() const {
		return bodyLength;
	}

	void body_length(size_t new_length) {
		bodyLength = new_length;
		if (bodyLength > maxBodyLength)
			bodyLength = maxBodyLength;
	}

	//header contains length of the body of the message
	bool decode_header() {
		char header[headerLength + 1] = "";
		strncat_s(header, dataArr, headerLength);
		bodyLength = atoi(header);
		if (bodyLength > maxBodyLength) {
			bodyLength = 0;
			return false;
		}
		return true;
	}

	void encode_header() {
		char header[headerLength + 1] = "";
		sprintf_s(header, headerLength + 1, "%4d", static_cast<int>(bodyLength));
		memcpy(dataArr, header, headerLength);
	}

private:
	char dataArr[headerLength + maxBodyLength];
	size_t bodyLength;
};