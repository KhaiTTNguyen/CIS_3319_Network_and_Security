# Khai Nguyen
#

# define a target for the application
#
all: tcp_server tcp_client as_tgs_server

# define a target to link the application
#
as_tgs_server: as_tgs_server.cpp des.cpp
	g++ as_tgs_server.cpp des.cpp -o as_tgs_server

tcp_server: server.cpp des.cpp
	g++ server.cpp des.cpp -o tcp_server

tcp_client: client.cpp des.cpp
	g++ client.cpp des.cpp -o tcp_client

# define a target to clean the directory
#
clean:
	rm -f *.o *.exe
#
# end of file
