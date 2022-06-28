SRC:=socket_server.cpp
server:${SRC}
	g++ $< -o server ../Diffie_Hellman/dh.o ../AES/aes.o -l gmp
clean:
	rm *.o server