#John Gallagher
##########################################################
#       Python Media Encryption/Decryption Schemes       # 
#                                                        #                                    
# This program has 3  main functions: ECB, CBC, and CTR. #
# Each function has name of the image to be encrypted    #
# already named. The file name for the encrypted and     #
# decrypted image are declared at the beginning of each  #
# function as well. Comments in lines 228-240 can be ran #
# to verify hash.                                        #
# Make sure to download Crypto Library for Python        #
# If you have any questions, please email#               #
# jgalla17@students.towson.edu                           #
#                                                        #
##########################################################

from Crypto.Cipher import AES
from Crypto.Util import Counter
def main():
    # all functions defined in 'dictionary'
    choices = {1: ECB, 2: CBC, 3: CTR, 4: QUIT}

    # Display Menu to the user
    displayMenu()
    choice = int(input("\n")) #options 1-4 in displaymenu()

    # Calling the selected mode of operation
    choices[choice]()

    ##################################################################################################

#ECB
def ECB():
    original = "Image1.bmp"  #name of image to be encrypted
    ciphered = "Image1_ECB_Encrypted.bmp" # name of new encrypted image
    deciphered = "Image1_ECB_Decrypted.bmp" # name of newly decrypted image
    # Given Key: (0x12345678)
    key = bytes("1234567812345678", "utf_8")  # Satisfies 16 byte requirement
    cipher = AES.new(key, AES.MODE_ECB)
    # open all 3 files
    original_file = open(original, "rb")
    encrypted_file = open(ciphered, "wb")
    decrypted_file = open(deciphered, "wb")
    # copy header information to both encrpyted and decrypted
    data = original_file.read(54) # reads header information, but none of the image data
    # copy header information to encrpyted and decrypted
    encrypted_file.write(data)
    decrypted_file.write(data)
    # Length given by calculating little endian value  starting at 0x36
    ##from assignment:
    ###"The next four bytes are 0x36 E8 20 00. This is the length of the file"
    original_file.seek(34)
    size = int.from_bytes(original_file.read(4), byteorder='little')
    # move past header information to picture data
    original_file.seek(54)
    i = 0

    # ENCRYPT #####################
    while (i < size):
        #read first 16 bytes as pixels
        pixels = original_file.read(16)
        #encrypt the bytes
        encrypted_pixels = cipher.encrypt(pixels)
        #save encrypted pixels
        encrypted_file.write(encrypted_pixels)
        # counter acts as pad
        i = i + 16
    print("Success: ", original, " was ENCRYPTED using ECB")
    encrypted_file.close()
    # DECRYPT ########################
    i = 0
    original_file = open(ciphered, "rb") # opens encrypted image in read mode
    original_file.seek(54) # skips header information
    while (i < size):
        # reads in first 16
        pixels = original_file.read(16)
        # decrypt the image data
        decrypted_pixels = cipher.decrypt(pixels)
        # save decrypted image data to decrypted_file
        decrypted_file.write(decrypted_pixels)
        # next 8 bytes
        i = i + 16
    print("\n\n", ciphered, "was DECRYPTED using ECB")
    #close all files
    encrypted_file.close()
    decrypted_file.close()
    original_file.close()
    another()
    ##################################################################################################


# Cipher Block Chaining
def CBC():
    original = "Image6.bmp"
    ciphered = "Image6_CBC_Encrypted.bmp"
    deciphered = "Image6_CBC_Decrypted.bmp"
    # Given Key (16 bytes)
    key = bytes("a184ee1ba184ee1b", 'utf-8')
    # Given Initialization Vector (16 bytes)
    IV = bytes("13579bde13579bde", 'utf-8')
    cipher = AES.new(key, AES.MODE_CBC, IV)
    # Opening all files
    original_file = open(original, "rb")
    encrypted_file = open(ciphered, "wb")
    decrypted_file = open(deciphered, "wb")

    # copy header info
    data = original_file.read(54)
    encrypted_file.write(data)
    decrypted_file.write(data)
    # little endian size
    original_file.seek(34)
    size = int.from_bytes(original_file.read(4), byteorder='little')
    # encrpyt image data
    original_file.seek(54)
    i = 0

    # Encrypt ########################
    while (i < size):
            # Reading 16 bytes to encrypt it using AES cipher
            # loop similar to EBC
        pixels = original_file.read(16)
        encrypted_pixels = cipher.encrypt(pixels)
        encrypted_file.write(encrypted_pixels)
        i = i + 16
    print("Success: ", original, "was encrypted using CBC")
    encrypted_file.close()
    original_file.close()
    # Decrypt ######################
    i = 0
    original_file = open(ciphered, "rb")
    original_file.seek(54)

    #decrypt loop similar to CBC as well
    while (i < size):
        cipher = AES.new(key, AES.MODE_CBC, IV)
        pixels = original_file.read(16)
        encrypted_pixels = cipher.decrypt(pixels)
        decrypted_file.write(encrypted_pixels)
        i = i + 16
    print("\n\n", original, "was decrypted correctly using Cipher Block Chaining Mode")
    original_file.close()
    decrypted_file.close()
    another() # asks user if they want to see another encryption/decryption scheme

    ##################################################################################################


# Counter
def CTR():
    original = "Image12.bmp"
    ciphered = "Image12_CTR_Encrypted.bmp"
    deciphered = "Image12_CTR_Decrypted.bmp"
    key = bytes("12df048a12df048a", 'utf-8') #Satisifes 16 bytes
    ctr = Counter.new(128, initial_value=0xff128eff)
    # print(ctr) length 16, prefix b,
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    # Opening files
    original_file = open(original, "rb")
    encrypted_file = open(ciphered, "wb")
    decrypted_file = open(deciphered, "wb")

    # Copy header
    data = original_file.read(54)
    encrypted_file.write(data)
    decrypted_file.write(data)
    # little endian file size
    original_file.seek(34)
    size = int.from_bytes(original_file.read(4), byteorder='little')
    # move to image information
    original_file.seek(54)
    i = 0

    # Encrypt ################
    while (i < size):
        pixels = original_file.read(16)
        encrypted_pixels = cipher.encrypt(pixels)
        encrypted_file.write(encrypted_pixels)
        i = i + 16
    print("Success: ", original, " was encrypted using CTR")
    encrypted_file.close()
    original_file.close()

    # Decrypt ################
    i = 0
    original_file = open(ciphered, "rb")
    original_file.seek(54)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    while (i < size):
        pixels = original_file.read(16)
        encrypted_pixels = cipher.decrypt(pixels)
        decrypted_file.write(encrypted_pixels)
        i = i + 16
    print("Success", original, " was decrypted using CTR")
    original_file.close()
    decrypted_file.close()
    another()


def QUIT():
    exit()

def another():
    option = int(input("Enter 1 to select another option from menu, any other number to quit: "))
    if (option == 1):
        main()
    else:
        QUIT()
def displayMenu():
    print("\n\Select an option to see encryption and decrpytion of image")
    print("*********************")
    print("1. ECB (Image1.bmp)")
    print("2. CBC (Image6.bmp)")
    print("3. CTR (Image12.bmp)")
    print("4. Quit")

def checkSHA256(a):
    import hashlib

    file = a
    sha256_hash = hashlib.sha256()
    with open(file, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
        print(sha256_hash.hexdigest())
#LETS GOOOOOOOOOOOOOOO
print("SHA256 value of image1.bmp: ")
checkSHA256("image1.bmp")
# print("SHA256 of image1_ECB_Decrypted.bmp: ")
# checkSHA256("image1_ECB_Decrypted.bmp")

print("SHA256 value of image6.bmp: ")
checkSHA256("image6.bmp")
#print("SHA256 of image6_CBC_Decrypted.bmp: ")
#checkSHA256("Image6_CBC_Decrypted.bmp")

print("SHA256 value of image12.bmp: ")
checkSHA256("image12.bmp")
#print("SHA256 of image12_CTR_Decrypted.bmp: ")
#checkSHA256("Image12_CTR_Decrypted.bmp")


main()