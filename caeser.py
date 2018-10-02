# Script:  caesar.py
# Desc:    encrypt and decrypt text with a Caesar cipher
#          using defined character set with index
# Author:  Jason Halley
# Created: 27/09/18
# note that you should add a module doc string!

import sys

charset="ABCDEFGHIJKLMNOPQRSTUVWXYZ" # characters to be encrypted
numchars=len(charset) # number of characters, for wrapping round

def caesar_encrypt(plaintext,key):
    """ciphers the text using the given key"""
    print (f'[*] ENCRYPTING - key: {key}; plaintext: {plaintext}')
       
    plaintext = plaintext.upper() # convert plaintext to upper case
    ciphertext=''    # initialise ciphertext as empty string   

    for ch in plaintext:
        if ch in charset:
            new = charset[(charset.index(ch) + key)%numchars]
        else:
            new=ch # do nothing with characters not in charset
        ciphertext=ciphertext+new
    print (f'[*] ciphertext: {ciphertext}')
    return ciphertext # returns ciphertext so it can be reused

def caesar_decrypt(ciphertext,key):
    """decrypts the ciphertext to plaintext using the given key"""
    # very similar to caesar_encrypt(), but shift left
    print (f'[*] DECRYPTING - key: {key}; ciphertext: {ciphertext}')
    ciphertext = ciphertext.upper()
    plaintext=''
    for ch in ciphertext:
        if ch in charset:
            new = charset[(charset.index(ch) - key)%numchars]
        else:
            new = ch
        plaintext = plaintext + new
    print (f'[*] plaintext: {plaintext}')
    return plaintext # returns plaintext so it can be reused

def caesar_crack(ciphertext):
    """tries every possible shift to show the correct text"""
   # key = 1
    for k in range(1,26):
        caesar_decrypt(ciphertext, k)
    
def main():
    # test cases
    #key=2
    #plain1 = 'Hello Suzanne'
    #cipher1 = 'IQQfOQtpKpIGXGtaQPG'
    #crackme = 'PBATENGHYNGVBAFLBHUNIRPENPXRQGURPBQRNAQGURFUVSGJNFGUVEGRRA' 
    # call functions with text cases
    #caesar_encrypt(plain1, key)
    #caesar_decrypt(cipher1,key)
    #caesar_crack(crackme)  # remove comment to test cracking


    print(' ________  ________  _______   ________  _______   ________          ________  ___  _______       ')
    print('|\   ____\|\   __  \|\  ___ \ |\   ____\|\  ___ \ |\   __  \        |\   __  \|\  \|\  ___ \      ')
    print('\ \  \___|\ \  \|\  \ \   __/|\ \  \___|\ \   __/|\ \  \|\  \       \ \  \|\  \ \  \ \   __/|     ')
    print(' \ \  \    \ \   __  \ \  \_|/_\ \_____  \ \  \_|/_\ \   _  _\       \ \   ____\ \  \ \  \_|/__   ')
    print('  \ \  \____\ \  \ \  \ \  \_|\ \|____|\  \ \  \_|\ \ \  \\  \|       \ \  \___|\ \  \ \  \_|\ \  ')
    print('   \ \_______\ \__\ \__\ \_______\____\_\  \ \_______\ \__\\ _\        \ \__\    \ \__\ \_______\ ')
    print('    \|_______|\|__|\|__|\|_______|\_________\|_______|\|__|\|__|        \|__|     \|__|\|_______| ')
    print('                                 \|_________|                                                     ')
    print('')
    print('A tool for encrypting, derypting, and cracking in the caeser cipher')
    print('')
    
    while True:
        print("1. Encrypt a string")
        print("2. Decrypt a string")
        print("3. Crack a cipher with unknown key")
        print("0. Quit the program")

        option = int(input("Please select an option >>>"))
        if option == 1:
            key = int(input("Please input the key/shift >>>"))
            plain = input("Please input the plain text to be ciphered >>>")
            caesar_encrypt(plain, key)
        elif option == 2:
            key = int(input("Please input the key/shift >>>"))
            cipher = input("Please input the cipher text to be decrypted >>>")
            caesar_decrypt(cipher, key)
        elif option == 3:
            # do cracking
            crack = input("Please enter the cipher text to be cracked >>>")
            caesar_crack(crack)
        elif option == 0:
            sys.exit("Goodbye")
        else:
            continue

# boilerplate
if __name__ == '__main__':
    main()
