# DES-Encryption-Program
A terminal program Implementing DES Encryption Algorithm using bitwise operations

## User guide
* compile and build the .cpp file in your terminal 
```
>g++ DES.cpp -o DES.exe
```
* The program requires 4 parameters:
  - Operation (encrypt/decrypt)
  - Plain text file name to be encrypted/decrypted 
  - Key file name (key should be in HEX format)
  - output file name

* to run the program run the .exe followed by the desired parameters in the same directory for example:
```
>DES.exe encrypt plain_text.txt key.txt encrypted.dat
```
or
```
>DES.exe decrypt encrypted.dat key.txt decrypted.txt
```
## Notes for optimization
This code can be optimized by reading files in binary format and using char arrays instead of strings
