# Khai Nguyen
#

# define a target for the application
#
all: myserver myclient main

# define a target to link the application
#

main: main.cpp 
	g++ main.cpp -o main

myserver: server.cpp function.cpp
	g++ server.cpp function.cpp -o myserver

myclient: client.cpp
	g++ client.cpp -o myclient

# define a target to clean the directory
#
clean:
	rm -f *.o *.exe
#
# end of file
