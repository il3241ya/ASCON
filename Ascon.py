from functools import reduce
import os

class Ascon():
    def __init__(self, Key: bytes, Nonce: bytes, AssociatedData: bytes):
        """
        Initializes an Ascon encryption object with the provided key, nonce, and associated data.

        Args:
            Key (bytes): Secret key of 128 bits or 16 bytes.
            Nonce (bytes): Public message number of 128 bits or 16 bytes.
            AssociatedData (bytes): Associated data with arbitrary length.

        Raises:
            AssertionError: If the size of the key or nonce is not 16 bytes.
        """

        self.Key = Key                       # Secret key (128 bits or 16 bytes)
        self.Nonce = Nonce                   # Public message number (128 bits or 16 bytes)
        self.AssociatedData = AssociatedData # Associated data (with arbitrary lenght)
        self.r = 8                           # self.r (data block size 16 bytes)
        self.a = 12                          # Rounds number
        self.b = 6                           # Rounds number

        self.RoundsConstants = [
            0x00000000000000f0,
            0x00000000000000e1,
            0x00000000000000d2,
            0x00000000000000c3,
            0x00000000000000b4,
            0x00000000000000a5,
            0x0000000000000096,
            0x0000000000000087,
            0x0000000000000078,
            0x0000000000000069,
            0x000000000000005a,
            0x000000000000004b
        ]
        # Check size of Key
        assert len(self.Key) == 16
        # Check size of Nonce
        assert len(self.Nonce) == 16

        self.IV = None
        self.k = len(self.Key) * 8
        self.State = [None, None, None, None, None]

        # Init IV
        self.IV = bytes(bytearray([self.k, self.r * 8, self.a, self.b])) + (4 * b'\x00') + self.Key + self.Nonce

        # Init State        
        self.State[0], self.State[1], self.State[2], self.State[3], self.State[4] = \
            [reduce(lambda acc, x: acc + (x[1] << ((8 - 1 - x[0]) * 8)), enumerate(bytearray(self.IV[8 * w: 8 * (w + 1)])), 0) for w in range(5)]
        
        self.State = self.permutation(self.State, self.a)
        
        _tp_key = \
            [reduce(lambda acc, x: acc + (x[1] << ((8 - 1 - x[0]) * 8)), enumerate(bytearray((24 * b'\x00' + self.Key)[8 * w: 8 * (w + 1)])), 0) for w in range(5)]
        for i in range(0, 5): self.State[i] ^= _tp_key[i]
        
        # Add AssociatedData
        self.AssociatedData_pad = self.AssociatedData + b'\x80' + b'\x00' * (self.r - (len(self.AssociatedData) % self.r) - 1)
        
        for j in range(0, len(self.AssociatedData), self.r):
            self.State[0] ^= reduce(lambda acc, x: acc + (x[1] << ((len(self.AssociatedData_pad[j: j + 8]) - 1 - x[0]) * 8)), enumerate(bytearray(self.AssociatedData_pad[j: j + 8])), 0)
            self.State = self.permutation(self.State, self.b)
        self.State[4] ^= 1

        self.InitState = self.State.copy()

        
    def permutation(self, State, Rounds):
        """
        Performs the permutation operation on the given state for the specified number of rounds.

        Args:
            State (list): Current state of the Ascon algorithm represented as a list of 5 64-bit words.
            Rounds (int): Number of rounds for the permutation operation.

        Returns:
            list: Updated state after performing the permutation operation.
        """
        
        for i in range(12 - Rounds, 12):
            # Addition of Constants 
            State[2] ^= self.RoundsConstants[i]

            # Substitution Layer
            # x0 ^= x4; x4 ^= x3; x2 ^= x1;
            State[0] ^= State[4]
            State[4] ^= State[3] 
            State[2] ^= State[1]

            # t0 = x0; t1 = x1; t2 = x2; t3 = x3; t4 = x4;
            tp_0 = State[0]
            tp_1 = State[1]
            tp_2 = State[2]
            tp_3 = State[3]
            tp_4 = State[4]

            # t0 =~ t0; t1 =~ t1; t2 =~ t2; t3 =~ t3; t4 =~ t4;
            tp_0 ^= 0XFFFFFFFFFFFFFFFF
            tp_1 ^= 0XFFFFFFFFFFFFFFFF
            tp_2 ^= 0XFFFFFFFFFFFFFFFF
            tp_3 ^= 0XFFFFFFFFFFFFFFFF
            tp_4 ^= 0XFFFFFFFFFFFFFFFF

            # t0 &= x1; t1 &= x2; t2 &= x3; t3 &= x4; t4 &= x0;
            tp_0 &= State[1]
            tp_1 &= State[2]
            tp_2 &= State[3]
            tp_3 &= State[4]
            tp_4 &= State[0]

            # x0 ^= t1; x1 ^= t2; x2 ^= t3; x3 ^= t4; x4 ^= t0;
            State[0] ^= tp_1
            State[1] ^= tp_2
            State[2] ^= tp_3
            State[3] ^= tp_4
            State[4] ^= tp_0

            # x1 ^= x0; x0 ^= x4; x3 ^= x2; x2 =~ x2;
            State[1] ^= State[0]
            State[0] ^= State[4]
            State[3] ^= State[2]
            State[2] ^= 0XFFFFFFFFFFFFFFFF

            # Diffusion Layer
            State[0] ^= ( (State[0] >> 19) | ((State[0] << 45) & 0xFFFFFFFFFFFFFFFF) ) ^ \
                        ( (State[0] >> 28) | ((State[0] << 36) & 0xFFFFFFFFFFFFFFFF) )
            State[1] ^= ( (State[1] >> 61) | ((State[1] << 3) & 0xFFFFFFFFFFFFFFFF) ) ^ \
                        ( (State[1] >> 39) | ((State[1] << 25) & 0xFFFFFFFFFFFFFFFF) )
            State[2] ^= ( (State[2] >> 1) | ((State[2] << 63) & 0xFFFFFFFFFFFFFFFF) ) ^ \
                        ( (State[2] >> 6) | ((State[2] << 58) & 0xFFFFFFFFFFFFFFFF) )
            State[3] ^= ( (State[3] >> 10) | ((State[3] << 54) & 0xFFFFFFFFFFFFFFFF) ) ^ \
                        ( (State[3] >> 17) | ((State[3] << 47) & 0xFFFFFFFFFFFFFFFF) )
            State[4] ^= ( (State[4] >> 7) | ((State[4] << 57) & 0xFFFFFFFFFFFFFFFF) ) ^ \
                        ( (State[4] >> 41) | ((State[4] << 23) & 0xFFFFFFFFFFFFFFFF) )
        return State
        

    def encrypt(self, PlainText: bytes) -> tuple:
        """
        Encrypts the given plaintext using the Ascon encryption algorithm.

        Args:
            PlainText (bytes): Plaintext to be encrypted.

        Returns:
            tuple: A tuple containing the ciphertext and authentication tag.
        """

        self.State = self.InitState.copy()   # Reset State to default
        self.PlainText = PlainText           # Plain text (with arbitrary lenght)

        self.CypherText = b''                # Cypher text (same lenght as plain text self.P)
        self.Tag = None                      # Authentification tag (128 bits or 16 bytes)

        self.PlainText_pad = self.PlainText + b'\x80' + b'\x00' * (self.r - (len(self.PlainText) % self.r) - 1)

        for j in range(0, len(self.PlainText_pad) - self.r, self.r):
            self.State[0] ^= reduce(lambda acc, x: acc + (x[1] << ((len(self.PlainText_pad[j: j + 8]) - 1 - x[0]) * 8)), enumerate(bytearray(self.PlainText_pad[j: j + 8])), 0)
            self.CypherText += bytes([self.State[0] // (256 ** (8 - 1 - i)) % 256 for i in range(8)])

            self.State = self.permutation(self.State, self.b)
        
        j = len(self.PlainText_pad) - self.r

        self.State[0] ^= reduce(lambda acc, x: acc + (x[1] << ((len(self.PlainText_pad[j: j + 8]) - 1 - x[0]) * 8)), enumerate(bytearray(self.PlainText_pad[j: j + 8])), 0)        
        self.CypherText += bytes([self.State[0] // (256 ** (8 - 1 - i)) % 256 for i in range(8)])[:len(self.PlainText) % self.r]
        
        # Get Tag
        self.State[self.r // 8] ^= reduce(lambda acc, x: acc + (x[1] << ((len(self.Key[0: 8]) - 1 - x[0]) * 8)), enumerate(bytearray(self.Key[0: 8])), 0)
        self.State[self.r // 8 + 1] ^= reduce(lambda acc, x: acc + (x[1] << ((len(self.Key[8: 16]) - 1 - x[0]) * 8)), enumerate(bytearray(self.Key[8: 16])), 0)
        tp_k = self.Key[16:] + b'\x00' * (24 - len(self.Key))
        self.State[self.r // 8 + 2] ^= reduce(lambda acc, x: acc + (x[1] << ((len(tp_k) - 1 - x[0]) * 8)), enumerate(bytearray(tp_k)), 0)
        
        self.State = self.permutation(self.State, self.a)

        self.State[3] ^= reduce(lambda acc, x: acc + (x[1] << ((len(self.Key[-16: -8]) - 1 - x[0]) * 8)), enumerate(bytearray(self.Key[-16: -8])), 0)
        self.State[4] ^= reduce(lambda acc, x: acc + (x[1] << ((len(self.Key[-8:]) - 1 - x[0]) * 8)), enumerate(bytearray(self.Key[-8: ])), 0)
        
        self.Tag = bytes([self.State[3] // (256 ** (8 - 1 - i)) % 256 for i in range(8)]) + \
                bytes([self.State[4] // (256 ** (8 - 1 - i)) % 256 for i in range(8)])

        return (self.CypherText + self.Tag, self.Tag)
        
    
    def decrypt(self, CypherText: bytes, Tag: bytes) -> tuple:
        """
        Decrypts the given ciphertext using the Ascon decryption algorithm and verifies the authenticity.

        Args:
            CypherText (bytes): Ciphertext to be decrypted.
            Tag (bytes): Authentication tag to be verified.

        Returns:
            tuple: A tuple containing the decrypted plaintext and an error flag indicating whether the decryption was successful.
        """
        
        self.State = self.InitState.copy()   # Reset State to default
        self.CypherText = CypherText         # Cypher text (with arbitrary lenght)
        self.Tag = Tag                       # Authentification tag (128 bits or 16 bytes)

        self.PlainText = b''                 # Plain text (same lenght as cupher text self.C)
        self.Eror = None                     # Error status (check tag correctness)

        self.CypherText_pad = self.CypherText + b'\x00' * (self.r - (len(self.CypherText) % self.r))

        for j in range(0, len(self.CypherText_pad) - self.r, self.r):
            CypherText_j = reduce(lambda acc, x: acc + (x[1] << ((len(self.CypherText_pad[j: j + 8]) - 1 - x[0]) * 8)), enumerate(bytearray(self.CypherText_pad[j: j + 8])), 0)        
            self.PlainText += bytes([(self.State[0] ^ CypherText_j) // (256 ** (8 - 1 - i)) % 256 for i in range(8)])
            self.State[0] = CypherText_j

            self.State = self.permutation(self.State, self.b)

        j = len(self.CypherText_pad) - self.r

        CypherText_pad_1 = 2 ** ((self.r - (len(self.CypherText) % self.r) - 1) * 8)
        CyherText_mask = (1 << (64 - (len(self.CypherText) % self.r) * 8)) - 1
        CypherText_j = reduce(lambda acc, x: acc + (x[1] << ((len(self.CypherText_pad[j: j + 8]) - 1 - x[0]) * 8)), enumerate(bytearray(self.CypherText_pad[j: j + 8])), 0)
        self.PlainText += bytes([(self.State[0] ^ CypherText_j) // (256 ** (8 - 1 - i)) % 256 for i in range(8)])[:(len(self.CypherText) % self.r)]
        self.State[0] = CypherText_j ^ (self.State[0] & CyherText_mask) ^ CypherText_pad_1
        
        # Get Tag
        self.State[self.r // 8] ^= reduce(lambda acc, x: acc + (x[1] << ((len(self.Key[0: 8]) - 1 - x[0]) * 8)), enumerate(bytearray(self.Key[0: 8])), 0)
        self.State[self.r // 8 + 1] ^= reduce(lambda acc, x: acc + (x[1] << ((len(self.Key[8: 16]) - 1 - x[0]) * 8)), enumerate(bytearray(self.Key[8: 16])), 0)
        tp_k = self.Key[16:] + b'\x00' * (24 - len(self.Key))
        self.State[self.r // 8 + 2] ^= reduce(lambda acc, x: acc + (x[1] << ((len(tp_k) - 1 - x[0]) * 8)), enumerate(bytearray(tp_k)), 0)
        
        self.State = self.permutation(self.State, self.a)

        self.State[3] ^= reduce(lambda acc, x: acc + (x[1] << ((len(self.Key[-16: -8]) - 1 - x[0]) * 8)), enumerate(bytearray(self.Key[-16: -8])), 0)
        self.State[4] ^= reduce(lambda acc, x: acc + (x[1] << ((len(self.Key[-8:]) - 1 - x[0]) * 8)), enumerate(bytearray(self.Key[-8: ])), 0)
        
        self.Tag = bytes([self.State[3] // (256 ** (8 - 1 - i)) % 256 for i in range(8)]) + \
                bytes([self.State[4] // (256 ** (8 - 1 - i)) % 256 for i in range(8)])


        if len(self.PlainText) > 0 and self.Tag == self.CypherText[-16:]: 
            self.Eror = False
        else: 
            self.Eror = True

        return (self.PlainText, self.Eror)


def main():
    mode = int(input(('Encrypt(1) | Decrypt(2) >> ')))

    while mode not in [1, 2]:
        print("Choose 1 or 2!")
        mode = int(input(('MODE: Encrypt(1) | Decrypt(2) >> ')))

    if mode == 1:
        
        while True:
            pth = input("The path to the text file: ")
            try:
                with open(pth, 'r') as file_in:
                    break
            except FileNotFoundError:
                print("This file does not exist!")
        
        with open(pth, 'r') as file_in:
            plaintext = file_in.read().encode('utf-8')
            
            key_gen = int(input("KEY: Random(1) | Your(2) >> "))
            while key_gen not in [1, 2]:
                print("Choose 1 or 2!")
                key_gen = int(input("KEY: Random(1) | Your(2) >> "))

            if key_gen == 1:
                key = bytes(bytearray(os.urandom(16)))
                with open("key.bin", 'wb') as file_out:
                    file_out.write(key)
                print("Key was written to the key.bin file")
            else:
                key = input("Enter a key with a length of 16 >> ").encode('utf-8')
                while len(key) != 16:
                    key = input("Enter a key with a LENGHT OF 16 >> ").encode('utf-8')

            associateddata = input("Enter the associated data >> ").encode('utf-8')
            nonce = bytes(bytearray(os.urandom(16)))
            with open("nonce.bin", 'wb') as file_out:
                file_out.write(nonce)
            print("Nonce was written to the nonce.bin file")

            asc = Ascon(key, nonce, associateddata)
            cypher_text, tag = asc.encrypt(plaintext)

        with open("output.bin", 'wb') as file_out:
            file_out.write(cypher_text)
            print("Cypher text (It was written to the output.bin file) << ", cypher_text)
        with open("tag.bin", 'wb') as file_tag:
            file_tag.write(tag)
            print("Tag (It was written to the tag.bin file) << ", tag)

    else:
        while True:
            pth = input("The path to the bin file: ")
            try:
                with open(pth, 'rb') as file_in:
                    break
            except FileNotFoundError:
                print("This file does not exist!")
        
        with open(pth, 'rb') as file_in:
            cypher_text = file_in.read()
            while True:
                key_pth = input("The path to the key.bin file: ")
                try:
                    with open(key_pth, 'rb') as file_in:
                        break
                except FileNotFoundError:
                    print("This file does not exist!")

            with open(key_pth, 'rb') as file_key:
                key = file_key.read()
            
            associateddata = input("Enter the associated data >> ").encode('utf-8')

            with open("nonce.bin", 'rb') as file_nonce:
                nonce = file_nonce.read()
            with open("tag.bin", 'rb') as file_tag:
                tag = file_tag.read()
            asc = Ascon(key, nonce, associateddata)
            plaintext, er = asc.decrypt(cypher_text, tag)
            with open("output.txt", 'wb') as file_out:
                print(plaintext)
                file_out.write(plaintext[2:-16])

if __name__ == "__main__":
    main()
