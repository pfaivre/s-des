# What is SDES?
In our modern computerized world, protection of our data has become essential.
Encryption is the most common way to achieve this. Numerous algorithms were invented to encrypt arbitrary data; the most used today is probably the AES (Advanced Encrypting Standard). It is powerful but also very hard to understand. It is the successor of the DES (Data Encryption Standard) less secure but also very complicated.
Unfortunately, they are hard to understand for someone who is willing to learn crytpography. That is why an algorithm named SDES (Simplified DES) was invented. It takes all the base principles of the DES (and by extension AES) but everything in it is simplified.

# How does it work?
As in every encrypting algorithms, SDES slices the message in chunks, and alter each of these given the key.
The key is a small piece of information that you keep secret to encrypt and decrypt the message.
In SDES, the key if of the size of 10 bits, for example `1001110100`.

## First step, generating the subkeys
Actually, SDES cannot use directly the key. It needs to compute two 8-bits subkeys which will be used in the process.

![Subkeys generation](docs/images/subkeys_generation_detailed.png)

The actions named P10, Shift and P8 are some very simple functions:

P10 performs a permutation (it changes the order of the bits) in this way:  
![P10](docs/images/P10.png)

Shift performs a rotation of the bits on each half of the key:  
![Shift](docs/images/Shift.png)  
Its parameter correspond of the number of times the rotation is performed.

P8 does an other permutation and keeps only 8 of the 10 orignal bits:  
![P8](docs/images/P8.png)

## Second step, encrypting the message


## Final step, decrypting the encypted message



