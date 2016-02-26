#!/usr/bin/env python

# This script will violate every message enciphered with an affine cipher
# it does a simple 'brute force' attack

import sys
import os

# This function calculates the modular inverse of a number
def mod_inv (num, mod):
    for x in range(0,mod + 1):
        if ((num*x)%mod == 1):
            return x
    sys.exit('[!!!] ERROR: modulo %d inverse of %d does not exists!' % (mod, num))

# Checking arguments
if not len(sys.argv) == 2:
    sys.exit('Usage: %s [FILE PATH]\nExecutes a brute force attack on the ciphered message contained into the file.' % sys.argv[0])

if sys.argv[1] == '-h' or sys.argv[1] == '--help':
    sys.exit('Usage: %s [FILE PATH]\nExecutes a brute force attack on the ciphered message contained into the file.' % sys.argv[0])

if not os.path.exists(sys.argv[1]):
    sys.exit('[!!!] ERROR: File %s was not found!' % sys.argv[1])

# Reading file and setting output file
msg_file = open(sys.argv[1],'r')
exploit = open('exploit.dat','w')
exploit.write('### EXPLOITING %s FILE ###\n' % sys.argv[1]);

# Brute force algorithm
for i in range(0,26):
    if (i%2 != 0) and (i != 13):
        for j in range(0,26):
            exploit.write('\n# TRYING KEY <%d,%d>\n# MESSAGE :\n' % (i,j))
            inv = mod_inv(i,26)
            for c in msg_file.read():
                v = ord(c)
                if (v >= 65) and (v <= 90):
                    # uppercase
                    cip = ((v - 65 - j)*inv + 26)%26 + 65
                elif (v >= 97) and (v <= 122):
                    # lowercase
                    cip = ((v - 97 - j)*inv + 26)%26 + 97
                else:
                    # other characters
                    cip = v
                # writing deciphered character
                exploit.write('%c' % cip)
            msg_file.seek(0)
