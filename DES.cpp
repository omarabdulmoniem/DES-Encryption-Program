#include <iostream>
#include <fstream>
#include <string>

using namespace std;


typedef unsigned long long u64;


// Array to hold the 16 keys
u64 keys[16];

// variable to hold the text
u64 text;

// array to carry the 64-bit blocks to be encrypted/decrypted
u64* blks_bf;
string* blks_bfs;

// array to carry the 64-bit blocks after encryption/decryption (encrypted/decrypted 64-bit blocks) 
u64* blks_af;

// variable to hold the cipher text (encrypted plain text)
string citext = "";

// variable to hold the decrypted plain text
string decrytext = "";

// variable to hold the binary version of the plain text
string text_binary;

//output file name
string out;


u64 power(u64 base, u64 po) {
    u64 result = 1;
    for (int i = 0; i < po; i++) {
        result *= base;
    }
    return result;
}


// Function to reverse a string
void reverseStr(string& str)
{
    int n = str.length();

    // Swap character starting from two
    // corners
    for (int i = 0; i < n / 2; i++)
        swap(str[i], str[n - i - 1]);
}


// function to convert text to binary
void strToBin(string s, string* st)
{
    int n = s.length();


    for (int i = 0; i <= n; i++)
    {
        // convert each character to its ASCII value
        int val = (unsigned char)s[i];

        // Convert ASCII value to binary
        string bin = "";
        while (val > 0)
        {
            (val % 2) ? bin.push_back('1') :
                bin.push_back('0');
            val /= 2;
        }
        // padding with 0's to the left to make all characters alligned to 8 bits
        while (bin.length() < 8) {
            bin.push_back('0');
        }
        reverseStr(bin);
        *st = *st + bin;
    }

}



// function to convert hexa key to binary
void HexToBin(string hexdec, string* key_binary)
{
    long int i = 0;

    while (hexdec[i]) {

        switch (hexdec[i]) {
        case '0':
            *key_binary = *key_binary + "0000";
            break;
        case '1':
            *key_binary = *key_binary + "0001";
            break;
        case '2':
            *key_binary = *key_binary + "0010";
            break;
        case '3':
            *key_binary = *key_binary + "0011";
            break;
        case '4':
            *key_binary = *key_binary + "0100";
            break;
        case '5':
            *key_binary = *key_binary + "0101";
            break;
        case '6':
            *key_binary = *key_binary + "0110";
            break;
        case '7':
            *key_binary = *key_binary + "0111";
            break;
        case '8':
            *key_binary = *key_binary + "1000";
            break;
        case '9':
            *key_binary = *key_binary + "1001";
            break;
        case 'A':
        case 'a':
            *key_binary = *key_binary + "1010";
            break;
        case 'B':
        case 'b':
            *key_binary = *key_binary + "1011";
            break;
        case 'C':
        case 'c':
            *key_binary = *key_binary + "1100";
            break;
        case 'D':
        case 'd':
            *key_binary = *key_binary + "1101";
            break;
        case 'E':
        case 'e':
            *key_binary = *key_binary + "1110";
            break;
        case 'F':
        case 'f':
            *key_binary = *key_binary + "1111";
            break;
        default:
            cout << "\nInvalid hexadecimal digit "
                << hexdec[i];
        }
        i++;
    }
}



string decToHex(u64 dec) {
    string hexa = "";
    for (int i = 0; i < 15; i++) {
        u64 sub_block = (dec >> (60 - i * 4)) & (0x0F);
        switch (sub_block) {
        case 0:
            hexa += "0";
            break;
        case 1:
            hexa += "1";
            break;
        case 2:
            hexa += "2";
            break;
        case 3:
            hexa += "3";
            break;
        case 4:
            hexa += "4";
            break;
        case 5:
            hexa += "5";
            break;
        case 6:
            hexa += "6";
            break;
        case 7:
            hexa += "7";
            break;
        case 8:
            hexa += "8";
            break;
        case 9:
            hexa += "9";
            break;
        case 10:
            hexa += "A";
            break;
        case 11:
            hexa += "B";
            break;
        case 12:
            hexa += "C";
            break;
        case 13:
            hexa += "D";
            break;
        case 14:
            hexa += "E";
            break;
        case 15:
            hexa += "F";
            break;
        }
    }
    return hexa;
}


// Function to get the binary version of a decimal number
string decToBin(u64 decimal)
{
    string binary;
    while (decimal != 0) {
        binary = (decimal % 2 == 0 ? "0" : "1") + binary;
        decimal = decimal / 2;
    }
    while (binary.length() < 4) {
        binary = "0" + binary;
    }
    return binary;
}


// Function to convert a number in binary to decimal
u64 binToDec(string binary)
{
    u64 decimal = 0;
    int counter = 0;
    int size = binary.length();
    for (int i = size - 1; i >= 0; i--)
    {
        if (binary[i] == '1') {
            decimal += power(2, counter);
        }
        counter++;
    }
    return decimal;
}



// KEY GENERATION

// Function to do a circular left shift by 1
u64 shift_left_once(u64 key_chunk) {
    u64 shifted = key_chunk;
    shifted = (key_chunk >> 27) | (shifted << 1);
    shifted &= ~(1 << 28);
    return shifted;
}

// Function to do a circular left shift by 2
u64 shift_left_twice(u64 key_chunk) {
    u64 shifted = key_chunk;
    shifted = (key_chunk >> 26) | (shifted << 2);
    shifted &= ~(1 << 28);
    shifted &= ~(1 << 29);
    return shifted;
}


void generate_keys(u64 key) {
    // The PC1 table 
    int pc1[56] = {
    57,49,41,33,25,17,9,
    1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,
    19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,
    7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,
    21,13,5,28,20,12,4
    };
    // The PC2 table
    int pc2[48] = {
    14,17,11,24,1,5,
    3,28,15,6,21,10,
    23,19,12,4,26,8,
    16,7,27,20,13,2,
    41,52,31,37,47,55,
    30,40,51,45,33,48,
    44,49,39,56,34,53,
    46,42,50,36,29,32
    };
    // Compressing the key using the PC1 table
    u64 perm_key = 0;
    for (int i = 0; i < 56; i++) {
        u64 req_bit = (key >> (63 - (pc1[i] - 1))) & 1;
        perm_key |= (req_bit << (55 - i));
    }
    // Dividing the key into two equal halves
    u64 left = (perm_key >> 28);
    u64 right = (perm_key << 35);
    right = (right >> 35);

    // Generating 16 keys
    for (int i = 0; i < 16; i++) {
        // For rounds 1, 2, 9, 16 the key half are shifted by one.
        if (i == 0 || i == 1 || i == 8 || i == 15) {
            left = shift_left_once(left);
            right = shift_left_once(right);
        }
        // For the rest of the rounds the key half are shifted by two
        else {
            left = shift_left_twice(left); 
            right = shift_left_twice(right);
        }
        // The two halfs are combined
        u64 combined_key = (left << 28) | right;

        u64 round_key = 0;
        // applying second permutation PC2
        for (int i = 0; i < 48; i++) {
            u64 req_bit = (combined_key >> (56 - pc2[i])) & 1;
            round_key |= (req_bit << (47 - i));
        }
        // storing the generated key
        keys[i] = round_key;
    }

}


// DES function

u64 DES() {
    // initial permutation table 
    int initial_permutation[64] = {
    58,50,42,34,26,18,10,2,
    60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6,
    64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,
    59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5,
    63,55,47,39,31,23,15,7
    };
    // expansion table
    int expansion_table[48] = {
    32,1,2,3,4,5,4,5,
    6,7,8,9,8,9,10,11,
    12,13,12,13,14,15,16,17,
    16,17,18,19,20,21,20,21,
    22,23,24,25,24,25,26,27,
    28,29,28,29,30,31,32,1
    };
    // The s-boxes
    int s_boxes[8][4][16] =
    { {
        14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
        0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
        4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
        15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13
    },
    {
        15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
        3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
        0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
        13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9
    },
    {
        10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
        13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
        13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
        1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12
    },
    {
        7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
        13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
        10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
        3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14
    },
    {
        2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
        14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
        4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
        11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3
    },
    {
        12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
        10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
        9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
        4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13
    },
    {
        4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
        13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
        1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
        6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12
    },
    {
        13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
        1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
        7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
        2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11
    } };
    // permutation table
    int permutation_table[32] = {
    16,7,20,21,29,12,28,17,
    1,15,23,26,5,18,31,10,
    2,8,24,14,32,27,3,9,
    19,13,30,6,22,11,4,25
    };
    // inverse permutation table
    int inverse_permutation[64] = {
    40,8,48,16,56,24,64,32,
    39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30,
    37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28,
    35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26,
    33,1,41,9,49,17,57,25
    };
    // Applying the initial permutation
    u64 perm = 0;
    for (int i = 0; i < 64; ++i) {
        perm |= (text >> (64 - initial_permutation[i]) & 1) << 64 - (i + 1);
    }

    // Dividing the result into two equal halves 
    u64 left = (perm >> 32);
    u64 right = (perm << 32);
    right = (right >> 32);

    // The plain text is encrypted in 16 rounds  
    for (int i = 0; i < 16; i++) {
        // The right half of the plain text is expanded
        u64 right_expanded = 0;
        for (int i = 0; i < 48; ++i) {
            u64 req_bit = ((right >> (31 - (expansion_table[i] - 1))) & 1);
            right_expanded |= (req_bit << (47 - i));
        };
        // The result is x_ored with a key
        u64 x_ored = (u64)keys[i] ^ (u64)right_expanded;
        u64 res = 0;
        // each s-box gets 6-bits and reduces them to 4
        for (int i = 0; i < 8; i++) {
            // getting the desired 6-bits
            u64 sub_block = (x_ored >> (42 - i * 6)) & (0x3F);
            // Finding row and column in s-box
            int row = ((sub_block >> 4) & 2) | (sub_block & 1);
            int col = ((sub_block >> 1) & 0x0F);
            u64 val = s_boxes[i][row][col];
            res |= val << (7 - i) * 4;
        }

        // second permutation is applied
        u64 perm2 = 0;
        for (int i = 0; i < 32; ++i) {
            perm2 |= (res >> (32 - permutation_table[i]) & 1) << 32 - (i + 1);
        }
        //The result is x_ored with the left half
        x_ored = perm2 ^ left;

        // The left and the right parts of the plain text are swapped except for the last round
        left = right;
        right = x_ored;
    }
    // The halves of the plain text are applied
    u64 combined_text = (right << 32) | left;
    u64 ciphertext = 0;
    // The inverse permuttaion is applied
    for (int i = 0; i < 64; ++i) {
        ciphertext |= (combined_text >> (64 - inverse_permutation[i]) & 1) << 64 - (i + 1);
    }
    // returning the cipher block
    return ciphertext;
}


// ENCRYPTION

void encrypt() {

    //applying DES to each 64-bit block
    for (u64 i = 0; i < (text_binary.length() / 64); i++) {
        text = blks_bf[i];
        u64 ct = DES();
        blks_af[i] = ct;
    }


    // converting the encrypted binary to plain text
    for (u64 i = 0; i < (text_binary.length() / 64); i++) {
        for (u64 y = 0; y < 8; y++) {
            char character = (blks_af[i] >> (64 - 8 * (y + 1))) & 0xFF;
            citext += (char)character;
        }
    }

    //generating encrypted file
    ofstream MyFile(out, ios::out | ios::binary);

    // Write to the file
    MyFile << citext;

    // Close the file
    MyFile.close();

    //generating hex file
    string hexa = "";
    for (u64 i = 0; i < (text_binary.length() / 64); i++) {
        hexa += decToHex(blks_af[i]);
    }

    ofstream MyFile2("hex.txt");
    MyFile2 << hexa;
    MyFile2.close();


    cout << "\nEncryption done succefully! plaintext and HEX encrypted files have been generated! \n";

}


// DECRYPTION

void decrypt() {
    //REVERSING THE ORDER OF KEYS
    int i = 15;
    int j = 0;
    while (i > j)
    {
        u64 temp = keys[i];
        keys[i] = keys[j];
        keys[j] = temp;
        i--;
        j++;
    }

    // Applying DES with reveresed keys order to each 64-bit block that was encrypted privously stored in blks_af(blocks after encryption)
    for (u64 i = 0; i < (text_binary.length() / 64); i++) {
        text = blks_bf[i];
        u64 decrypted = DES();
        blks_af[i] = decrypted;
    }

    // converting the decrypted binary to plain text
    for (u64 i = 0; i < (text_binary.length() / 64); i++) {
        for (u64 y = 0; y < 8; y++) {
            char character = (blks_af[i] >> (64 - 8 * (y + 1))) & 0xFF;
            decrytext += (char)character;
        }
    }

    //generating encrypted file
    ofstream MyFile(out);

    // Write to the file
    MyFile << decrytext;

    // Close the file
    MyFile.close();

    cout << "\nDecryption done succefully! decrypted file has been generated! \n";
}


// Main function

int main(int argc, char* argv[]) {


    // encrypt or decrypt
    string operation = argv[1];
    // getting input file
    string input_name = argv[2];
    // getting the key
    string input_kname = argv[3];
    // getting dat file name to be generated
    out = argv[4];

    // printing operation
    if (operation == "encrypt" || operation == "Encrypt") {
        cout << endl << "Encrypting..." << endl;
    }
    else if (operation == "decrypt" || operation == "Decrypt") {
        cout << endl << "Decrypting..." << endl;
    }

    // getting text from file
    string text;
    string path = input_name;
    ifstream in(path, ios::in | ios::binary);
    char mychar;
    while (!in.eof()) {
        mychar = in.get();
        text = text + mychar;
    }

    // getting key from file
    ifstream file;
    file.open(input_kname);
    string key;
    if (file.is_open()) {
        getline(file, key);
    }
    else {
        cout << "\nCouldn't open file\n";
    }

    //converting the key from hex to binary
    string key_binaryst;
    HexToBin(key, &key_binaryst);

    //generting 16 rounds keys
    u64 key_binary = binToDec(key_binaryst);
    generate_keys(key_binary);


    // converting the input text to binary
    strToBin(text, &text_binary);

    // padding with 0's to make 64 bit blocks
    text_binary.replace(text_binary.length() - 16, 8, "00000000");
    while (text_binary.length() % 64 != 0) {
        text_binary.push_back('0');
    }


    // creating array to carry the 64 bit blocks before and after DES 

    //string version of the blocks
    blks_bfs = new string[text_binary.length() / 64];

    // u64 version
    blks_bf = new u64[text_binary.length() / 64];
    blks_af = new u64[text_binary.length() / 64];


    // dividing the binary to 64 bit blocks
    for (u64 i = 0; i < (text_binary.length() / 64); i++) {
        blks_bfs[i] = text_binary.substr(i * 64, 64);
    }

    // decimal 64-bit version
    for (u64 i = 0; i < (text_binary.length() / 64); i++) {
        u64 decversion = (u64)binToDec(blks_bfs[i]);
        blks_bf[i] = decversion;
    }

    // Applying the choosen operation
    if (operation == "encrypt" || operation == "Encrypt") {
        encrypt();
    }
    else if (operation == "decrypt" || operation == "Decrypt") {
        decrypt();
    }

}