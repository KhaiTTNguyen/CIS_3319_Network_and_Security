#include "header.h"

//Client side
int main(int argc, char *argv[])
{
    //we need 2 things: ip address and port number, in that order
    if(argc != 4)
    {
        cerr << "Usage: ip_address port key_file" << endl; exit(0); 
    } //grab the IP address and port number 
    char *serverIp = argv[1]; int port = atoi(argv[2]); 

    FILE * fp;
    // Open the file  
    fp = fopen(argv[3], "r");
    if (fp == NULL) { 
        printf("Could not open file %s", argv[3]); 
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
    cout << "Key is" << key << endl;
    generate_keys(key, encryption_round_keys);
    
    int i = 15;
    int j = 0;
    while(i > -1){
        decryption_round_keys[j] = encryption_round_keys[i];
        i--;
        j++;
    }

    /*------------Key for HMAC encrypt---------*/
    std::string HMAC_key = "key";

    //create a message buffer 
    char msg[MAX_BUFFER_LENGTH]; 
    //setup a socket and connection tools 
    struct hostent* host = gethostbyname(serverIp); 
    sockaddr_in sendSockAddr;   
    bzero((char*)&sendSockAddr, sizeof(sendSockAddr)); 
    sendSockAddr.sin_family = AF_INET; 
    sendSockAddr.sin_addr.s_addr = inet_addr(inet_ntoa(*(struct in_addr*)*host->h_addr_list));
    sendSockAddr.sin_port = htons(port);
    int clientSd = socket(AF_INET, SOCK_STREAM, 0);
    //try to connect...
    int status = connect(clientSd,
                         (sockaddr*) &sendSockAddr, sizeof(sendSockAddr));
    if(status < 0)
    {
        cout<<"Error connecting to socket!"<<endl; 
        exit(0);
    }
    cout << "Connected to the server!" << endl;
    int bytesRead, bytesWritten = 0;
    struct timeval start1, end1;
    gettimeofday(&start1, NULL);
    while(1)
    {
        /*------------------------ Encryption ----------------------------*/
        cout << ">";
        string data;
        getline(cin, data);

        string binText = TextToBinaryString(data);
        std::string sha2hmac = hmac<SHA256>(data, key);
        string binHMAC = HextoBinary(sha2hmac);
        string binToEncrypt = binText + binHMAC; 

        string encryptedMessage = generateCipher(binToEncrypt, encryption_round_keys);

        // print out shared key, mesage, encrypted text
        cout << endl;
        cout << "Shared DES key is :" << key << endl;
        cout << "HMAC is :" << binHMAC << endl;
        // cout << "Plain text message is " << data << endl;
        // cout << "Cipher text is " << encryptedMessage << endl;

        //send the message to client
        strcpy(msg, encryptedMessage.c_str());
        bytesWritten += send(clientSd, (char*)&msg, strlen(msg), 0);
        
        cout << "Awaiting server response..." << endl;
        memset(&msg, 0, sizeof(msg));//clear the buffer
        /* ------------------------- Decryption ------------------------------*/
        bytesRead += recv(clientSd, (char*)&msg, sizeof(msg), 0);
        string decrypted = generatePlain(string(msg),decryption_round_keys);
        
        string receivedHMAC = decrypted.substr(decrypted.length() - 256, 256); 
        string assumedBinText = decrypted.substr(0, decrypted.length() - receivedHMAC.length());
    
        cout << endl;
        cout << "Shared DES key is :" << key << endl;
        // cout << "Cipher text is " << string(msg) << endl;
        cout << "Correct! Received HMAC is " << receivedHMAC << endl;
        cout << "Client Plain text message is: " << BinaryStringToText(assumedBinText) << endl;
    }

    close(clientSd);
    return 0;    
}