SRC:=socket_client.cpp
client:${SRC}
	g++ $< -o client ../Diffie_Hellman/dh.o ../AES/aes.o -l gmp
clean:
	rm *.o client