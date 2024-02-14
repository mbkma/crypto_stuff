CC = g++

generate-private-key:
	openssl ecparam -genkey -name prime256v1 -noout -out private_key.pem; \

build:
	$(CC) sign_message.cpp -lssl -lcrypto; \

run:
	./a.out; \