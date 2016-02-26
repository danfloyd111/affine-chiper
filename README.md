# affine-chiper

An implementation of the historycal affine chiper written in C and a Brute Force Attack written in Python

"The affine cipher is a type of monoalphabetic substitution cipher, wherein each letter in an alphabet is mapped to its numeric 
equivalent, encrypted using a simple mathematical function, and converted back to a letter. The formula used means that each 
letter encrypts to one other letter, and back again, meaning the cipher is essentially a standard substitution cipher with a rule
governing which letter goes to which. As such, it has the weaknesses of all substitution ciphers. Each letter is enciphered with 
the function (ax+b)\mod(26), where b is the magnitude of the shift." - taken from Wikipedia - for further information see [here](https://en.wikipedia.org/wiki/Affine_cipher).

In this repository you can find my version of the cipher and a simple script in written in Python that forces the cipher in a few seconds doing a [Brute Force Attack](https://en.wikipedia.org/wiki/Brute-force_attack).
