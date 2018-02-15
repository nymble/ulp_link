#!/usr/bin/env python
""" ulp_vectors.py

    No rights reserved. (c) 2018 by Paul A. Lambert
"""
from aes_siv import siv_encrypt, siv_decrypt, AES_SIV
from hashlib import sha256
from os import urandom

# defined sizes are in octets
UDS_SIZE = 32
UDI_SIZE = 16
HEADER_ID_SIZE = 6
REPLAY_NONCE_SIZE = 6


def id_hash(uds):
    """ The hash function used the generate an identifier from
        the secret key.
    """
    # sha256 for now, later Blake2b would be much faster
    return sha256(uds).digest()[0:UDI_SIZE]   # first 16 octets / 128 bits


class ULPD:
    def __init__(self):
        """ The simulated creation of a ULPD """
        self._uds = os.urandom(UDS_SIZE)    # unique device secret
        self.udi = kdf(_uds)
        self.replay_nonce = REPLAY_NONCE_SIZE*"\00"
    
    def encrypt_frame(self, frame_data):
        """ """
        id = udi[0:HEADER_ID_SIZE]       # truncate udi to 6 octets
        key = self._uds
        ad = [id]           # protected additional data is just the id, perhaps more later
        
        cipher_text = siv_encrypt(key, frame_data, ad)
        return id + cipher_text   # concatenation id to encrypted frame
    
    def process_recieved_frame(self, encrypted_frame):
        id = frame[0:HEADER_ID_SIZE]
        if id != self.udi[0:HEADER_ID_SIZE]:
            raise "Wrong id on frame, not for this device"




class AD:
    def __init__(ulpd):
        """ Simulation of paired AD
            AD is passed a particular ULPD instance to simulate
            pairing process to access the unique device secret (udi)
        """
        uds = ulpd._uds



class TestVectorsRFC5297(unittest.TestCase):
    """ Test Vectors from RFC 5297 """
    def test_A1(self):
        """ A.1. Deterministic Authenticated Encryption Example """
        key = 'fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'.decode('hex')
        ad  = '101112131415161718191a1b1c1d1e1f2021222324252627'.decode('hex')
        pt  = '112233445566778899aabbccddee'.decode('hex')
        iv_ct = siv_encrypt(key, pt, [ad])
        known_ct = '85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c'.decode('hex') 
        
        self.assertEqual( iv_ct, known_ct )
       
        pt2 = siv_decrypt(key, iv_ct, [ad])
        self.assertEqual(  pt, pt2 )

    def test_A2(self):
        """ A.2. Nonce-based Authenticated Encryption Example """
        key = '7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f'.decode('hex')
        ad1 = '00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100'.decode('hex')
        ad2 = '102030405060708090a0'.decode('hex')
        nonce = '09f911029d74e35bd84156c5635688c0'.decode('hex')
        ad = [ad1, ad2, nonce]
        pt = '7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553'.decode('hex')
        iv_ct = siv_encrypt(key, pt, ad)
        known_ct = '7bdb6e3b432667eb06f4d14bff2fbd0fcb900f2fddbe404326601965c889bf17dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d'.decode('hex') 
        
        self.assertEqual(  iv_ct, known_ct )
        
        pt2 = siv_decrypt(key, iv_ct, ad)  
        self.assertEqual(  pt, pt2 )
    
    def test_Edges(self):
        """ Test edge conditions - zero lengths """
        # zero length plian text, multiple ad
        key = '7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f'.decode('hex')
        pt = ''
        ad1 = 'abcd'.decode('hex')
        ad2 = 'beef'.decode('hex')
        nonce = '09f911029d74e35bd84156c5635688c0'.decode('hex')
        ad = [ad1, ad2, nonce]
        
        iv_ct = siv_encrypt(key, pt, ad)
        pt2 = siv_decrypt(key, iv_ct, ad)
        
        self.assertEqual(  pt, pt2 )
        
        # no ad
        iv_ct = siv_encrypt(key, 'a', [])
        pt2 = siv_decrypt(key, iv_ct, [])
        self.assertEqual(  'a', pt2 )
        
        
class Test_AES_SIV_Class(unittest.TestCase):
    def test_simple(self):
        key = 'fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'.decode('hex')
        aead_cipher = AES_SIV(key)   
        ad1 = '0011'.decode('hex')
        ad2 = '1023'.decode('hex')
        ad = [ad1, ad2 ]
        message = 'testing 123'
        cipher_text = aead_cipher.encrypt( message, ad)
        recovered_plain_text = aead_cipher.decrypt( cipher_text, ad)
        self.assertEqual( message, recovered_plain_text )
def main():
    """ Generate test vectors """
    ulpd = ULPD()   # an instance of ulpd with random 'uds'
                    # TBD - for predictable vectors this needs to seeded
    ad = AD(ulpd)   # instance of AD keyed for ulpd

    


        
        
        
        
    
if __name__ == '__main__':
    main()
