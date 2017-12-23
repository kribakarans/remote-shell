
all:
	cc -g server.c        -pthread     -o server
	cc -g client.c -pthread -lreadline -o client

clean:
	rm -f *.o 
	rm -f server
	rm -f client
