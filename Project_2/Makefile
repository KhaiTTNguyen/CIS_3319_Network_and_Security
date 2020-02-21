# Khai Nguyen
#

# define a target for the application
#
all: tcp_server tcp_client

# define a target to link the application
#

tcp_server: server.cpp function.cpp
	g++ server.cpp function.cpp sha256.cpp -o tcp_server

tcp_client: client.cpp function.cpp
	g++ client.cpp function.cpp sha256.cpp -o tcp_client

# define a target to clean the directory
#
clean:
	rm -f *.o *.exe
#
# end of file
