# Create key for XOR function on web server
Choose your own set of bytes for the thrill :))))
```
echo -n -e '\x31\x37\x30\x31\x32\x37\x31\x30\x30\x30\x30\x30\x5a\x30\x63\x31' > key.bin
```
Copy the key to XORRawFileEncoder to `key` variable.

# Encode the raw binary of your C2 Framework
Compile `XORRawFileEncoder` in VS using C# (.NET Framework) project template. Then copy the raw binary file to the same directory as compiled program and run it:
```
.\XORRawFileEncoder.exe .\stager.bin
```
The output file will be encoded with key that's included in the application.
Serve the `encoded_stager.bin` and `key.bin` on your web server.

# Compile XORProcessHypnosisStaged loader
Compile XORProcessHypnosisStaged loader using VS with C++ Console App.
Remember to change the addresses from which loader will download encoded stager binary and key binary.
