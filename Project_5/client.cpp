#include "header.h"

//Client side
int main(int argc, char *argv[])
{
    //we need 2 things: ip address and port number, in that order
    if(argc != 6){  cerr << "Usage: ip_address port ip_address_2 port_2 key_file" << endl; exit(0); } 

    
    //----------------------- load the key for DES ------------------------
    FILE * fp = fopen(argv[5], "r");
    if (fp == NULL) { 
        printf("Could not open file %s", argv[3]); 
        return 0; 
    } 

    string key = "";
    char chunk[MAX_BUFFER_LENGTH];
    while(fgets(chunk, sizeof(chunk), fp) != NULL) {    key += string(chunk);   }
    // Close the file 
    fclose(fp); 

    string encryption_round_keys[ITERATION];
    string decryption_round_keys[ITERATION];
    generate_keys(key, encryption_round_keys);
    
    int i = 15;
    int j = 0;
    while(i > -1){ decryption_round_keys[j] = encryption_round_keys[i];
        i--;
        j++;
    }
    //----------------------------------------------------------------------

    //grab the IP address and port number 
    char *serverIp = argv[1]; int port = atoi(argv[2]);         // tgs
    char *serverIp_2 = argv[3]; int port_2 = atoi(argv[4]);     // server
    
    // char *serverIp = "127.0.0.1"; int port = 8888;      // tgs
    // char *serverIp_2 = "127.0.0.1"; int port_2 = 9999;  // server

    //create a message buffer 
    char msg[MAX_BUFFER_LENGTH]; 
    char msg_2[MAX_BUFFER_LENGTH]; 
    //setup a socket and connection tools 
    struct hostent* host = gethostbyname(serverIp); struct hostent* host_2 = gethostbyname(serverIp_2); 
    
    sockaddr_in sendSockAddr; sockaddr_in sendSockAddr_2;   
    bzero((char*)&sendSockAddr, sizeof(sendSockAddr)); bzero((char*)&sendSockAddr_2, sizeof(sendSockAddr_2)); 
    
    sendSockAddr.sin_family = sendSockAddr_2.sin_family = AF_INET; 
    sendSockAddr.sin_addr.s_addr = inet_addr(inet_ntoa(*(struct in_addr*)*host->h_addr_list)); 
    sendSockAddr_2.sin_addr.s_addr = inet_addr(inet_ntoa(*(struct in_addr*)*host_2->h_addr_list));

    sendSockAddr.sin_port = htons(port);sendSockAddr_2.sin_port = htons(port_2);
    
    int clientSd = socket(AF_INET, SOCK_STREAM, 0);
    int clientSd_2 = socket(AF_INET, SOCK_STREAM, 0);
    
    //try to connect...
    int status = connect(clientSd,(sockaddr*) &sendSockAddr, sizeof(sendSockAddr));             // for tgs
    int status_2 = connect(clientSd_2,(sockaddr*) &sendSockAddr_2, sizeof(sendSockAddr_2));     // for server
    
    if(status < 0){cout<<"Error connecting to socket_1!"<<endl; exit(0);}
    if(status_2 < 0){cout<<"Error connecting to socket_2!"<<endl; exit(0);}

    cout << "Connected to the as_tgs_server!" << endl;
    cout << "Connected to the server!" << endl;   

    long bytesRead, bytesWritten = 0;

    /*-------------------------------Kerberos Authentication----------------------------*/
    /*  Phase 1: IDc, ID tgs, Timestamp_1 */
    time_t ts_1 = time(NULL);
    string phase_1 = string(ID_c) + string(ID_tgs) + to_string(ts_1); strcpy(msg, phase_1.c_str());
    bytesWritten += send(clientSd, (char*)&msg, strlen(msg), 0); 

    /* Phase 2: as_tgs */
    // bytesRead += recv(clientSd, (char*)&msg, sizeof(msg), 0);
    // cout << "response from ags_server: " << BinaryStringToText(generatePlain(string(msg),decryption_round_keys)) << endl;

    /* Phase 3: */

    /*---------------------------K_Auth done-------------------------*/
    while(1)
    {
        /*------------------------ Encryption ----------------------------*/
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
        bytesWritten += send(clientSd, (char*)&msg, strlen(msg), 0);
        bytesWritten += send(clientSd_2, (char*)&msg, strlen(msg), 0);

        /* ------------------------- Decryption ------------------------------*/
        memset(&msg, 0, sizeof(msg));//clear the buffer
        bytesRead += recv(clientSd, (char*)&msg, sizeof(msg), 0);
        string decrypted = generatePlain(string(msg),decryption_round_keys);
        cout << "ags_server: " << BinaryStringToText(decrypted) << endl;
        
        memset(&msg, 0, sizeof(msg));//clear the buffer
        bytesRead += recv(clientSd_2, (char*)&msg, sizeof(msg), 0);
        string decrypted_2 = generatePlain(string(msg),decryption_round_keys);
        cout << "server: " << BinaryStringToText(decrypted_2) << endl;
    }

    close(clientSd);
    return 0;    
}