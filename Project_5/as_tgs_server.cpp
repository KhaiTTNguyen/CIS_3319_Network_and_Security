#include "header.h"

using namespace std;
//Server side
int main(int argc, char *argv[])
{
    //for the server, we only need to specify a port number
    if(argc != 3)
    {
        cerr << "Usage: port key_file" << endl;
        exit(0);
    }
    //grab the port number
    int port = atoi(argv[1]);
    
    // ---------------------- load the key for DES -------------------------
    FILE * fp;
    // Open the file  
    fp = fopen(argv[2], "r");
    if (fp == NULL) { 
        printf("Could not open file %s", argv[2]); 
        return 0; 
    } 

    string key = "";
    char chunk[MAX_BUFFER_LENGTH];
    while(fgets(chunk, sizeof(chunk), fp) != NULL) {
        key += string(chunk);
    }

    // Close the file 
    fclose(fp); 

    //----------------------- load the key for DES ------------------------
    string encryption_round_keys[ITERATION];
    string decryption_round_keys[ITERATION];

    generate_keys(key, encryption_round_keys);
    
    int i = 15;
    int j = 0;
    while(i > -1){
        decryption_round_keys[j] = encryption_round_keys[i];
        i--;
        j++;
    }

    //buffer to send and receive messages with
    char msg[MAX_BUFFER_LENGTH];
     
    //setup a socket and connection tools
    sockaddr_in servAddr;
    bzero((char*)&servAddr, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons(port);
 
    //open stream oriented socket with internet address
    //also keep track of the socket descriptor
    int serverSd = socket(AF_INET, SOCK_STREAM, 0);
    if(serverSd < 0)
    {
        cerr << "Error establishing the server socket" << endl;
        exit(0);
    }

    // in case there is an existing server socket - reuse it
    // if not, when recreating socket with same code, bind error happens, only after 30-60 seconds a new socket is created successfully.
    int yes=1;
    if (setsockopt(serverSd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
        perror("setsockopt");
        exit(1);
    }

    //bind the socket to its local address
    int bindStatus = bind(serverSd, (struct sockaddr*) &servAddr, 
        sizeof(servAddr));
    if(bindStatus < 0)
    {
        cerr << "Error binding socket to local address" << endl;
        exit(0);
    }
    cout << "Waiting for a client to connect..." << endl;
    //listen for up to 5 requests at a time
    listen(serverSd, 5);
    //receive a request from client using accept
    //we need a new address to connect with the client
    sockaddr_in newSockAddr;
    socklen_t newSockAddrSize = sizeof(newSockAddr);
    //accept, create a new socket descriptor to 
    //handle the new connection with client
    int newSd = accept(serverSd, (sockaddr *)&newSockAddr, &newSockAddrSize);
    if(newSd < 0)
    {
        cerr << "Error accepting request from client!" << endl;
        exit(1);
    }
    cout << "Connected with client!" << endl;
    //lets keep track of the session time
    struct timeval start1, end1;
    gettimeofday(&start1, NULL);
    //also keep track of the amount of data sent as well
    int bytesRead, bytesWritten = 0;
    while(1)
    {
        //receive a message from the client (listen)
        memset(&msg, 0, sizeof(msg));//clear the buffer
         /* ------------------------- Decryption ------------------------------*/
        bytesRead += recv(newSd, (char*)&msg, sizeof(msg), 0);
        string decrypted = generatePlain(string(msg),decryption_round_keys);
        // cout << endl;
        // cout << "Shared key is :" << key << endl;
        // cout << "Cipher text is " << string(msg) << endl;
        cout << "Client: " << BinaryStringToText(decrypted) << endl;

        /*------------------------ Encryption ----------------------------*/
        memset(&msg, 0, sizeof(msg)); //clear the buffer
        cout << ">";
        string data;
        getline(cin, data);

        string binary_text = TextToBinaryString(data);
        string encryptedMessage = generateCipher(binary_text, encryption_round_keys);

        // print out shared key, mesage, encrypted text
        // cout << endl;
        // cout << "Shared key is :" << key << endl;
        // cout << "Plain text message is " << data << endl;
        // cout << "Cipher text is " << encryptedMessage << endl;

        //send the message to client
        strcpy(msg, encryptedMessage.c_str());
        bytesWritten += send(newSd, (char*)&msg, strlen(msg), 0);
    }
    //we need to close the socket descriptors after we're all done
    gettimeofday(&end1, NULL);
    close(newSd);
    close(serverSd);

    return 0;   
}