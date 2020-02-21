
#include "header.h"

 // for std::cout only, not needed for hashing library 
 int main(int, char**) {   
    string encryption_round_keys[ITERATION];
    string decryption_round_keys[ITERATION];

    // A 64 bit key
	string DES_key= "1010101010111011000010010001100000100111001101101100110011011101";
	// Calling the function to generate 16 keys
  	generate_keys(DES_key,encryption_round_keys);
      
    int i = 15;
    int j = 0;
    while(i > -1){
        decryption_round_keys[j] = encryption_round_keys[i];
        i--;
        j++;
    }


    /*------------------------HMAC encryption---------------------------*/
    
    std::string msg = "The quick brown fox jumps over the lazy dog";
    std::string key = "key";
    std::string sha2hmac = hmac<SHA256>(msg, key);


    // create HMAC 
    // cout << "SHA256 HMAC: " << sha2hmac << endl;
    // cout << "String length " << sha2hmac.length() << endl;

    // convert hex to binary && convert string 
    string binText = TextToBinaryString(msg);
    string binHMAC = HextoBinary(sha2hmac);

    cout << "Text before encrypt " << msg << endl;
    cout << "msg length " << msg.length() << endl;

    // attach HMAC to converted string
    string binToEncrypt = binText + binHMAC; 

    // DES encrypt 
    string cipherText = generateCipher(binToEncrypt, encryption_round_keys);

    // DES decrypt
    string decrypted = generatePlain(cipherText,decryption_round_keys);
    
    cout << endl;
    
    // cut off HMAC
    string receivedHMAC = decrypted.substr(decrypted.length() - 256, 256); 
    string assumedBinText = decrypted.substr(0, decrypted.length() - receivedHMAC.length());
    

    // create HMAC 
    string assumedPlainText = BinaryStringToText(assumedBinText);

    cout << "assumed plaintext  after decrypt " << assumedPlainText << endl;
    cout << "assumedPlaintext length " << assumedPlainText.length() << endl;
    /*
    std::string msg = "The quick brown fox jumps over the lazy dog";
    std::string key = "key";
    std::string sha2hmac = hmac<SHA256>(msg, key);
    */
    cout << "HMAC " << sha2hmac << endl;
    //cout << "received HMAC" << BinaryToHex(receivedHMAC) << endl;
    
    // std::string sha2hmac_new = hmac<SHA256>(assumedPlainText,key);
    // compare
    // cout << receivedHMAC << endl;

    


    //std::string sha2hmac = hmac<SHA256>(msg, key);

    return 0; 
} 
