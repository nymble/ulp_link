#!/usr/bin/env python
""" ulp_link_proto_ratchet.py

    A link security protocol for ultra-low-power devices
    with no persistant memory and frequent resets.
    
    The protocol functions:
       encrypt_frame(message_data)
       decrypt_frame(encrypted_frame)


    No Rights Reserved. (c) 2018 by Paul A. Lambert
"""
from aes_siv import siv_encrypt, siv_decrypt, AES_SIV
from hashlib import sha256 #
import os
from binascii import b2a_hex

UDS_SIZE = 32 # size of Unique Device Secret (UDS) in octets
UDI_SIZE = 16 # size of Unique Device Identifier (UDI) in octets

# Frame field sizes in octets
HEADER_ID_SIZE =          6   #
HEADR_SIV_SIZE =         16   # 128-bit security for MAC collisions
REPLAY_VALUE_SIZE = 4 #   8   two fields of this size: 'rt'  and 'rr'
#                   --------
#                        30 octets total overhead

# On reset 'rt' is set to a random value and 'rr' to a string of all zeros
ZERO_REPLAY_FIELD = REPLAY_VALUE_SIZE*'\00' # octet string of zeros

REPLAY_VALUE_LIFETIME = 1 # transmitted frames until random change in replay value

# replay value states used to implement 'ratchet'
NEW = 1        # state after changing my_replay_value
ECHOED = 2     # state after seeing changed value echoed


class ULPLinkProto:
    """ Symmetric key based secure link protocol.
          - Designed for memoryless devices with frequent power loss
          - SIV mode encryption for nonce misuse resistance
          - Ratcheting replay nonce exchange for replay protection
    """
    def reset(self):
        """ On power loss or forced reset the protocol starts over
            by setting the local replay protection value to a
            random value and the peer value to zero.
        """
        # reset my_replay protection value, and ensure it is not
        # randomly set to all zeros
        self.change_my_replay_value()  # sets replay, state and tramsmit count

        # the peer value is not known so set to zeros
        self.peer_replay_value = ZERO_REPLAY_FIELD
    
    def encrypt_frame(self, message_data):
        """ Encrypt message_data using a SIV AEAD mode
            with 'ratcheting replay protection' and return frame
            for transmission.
        """
        # the 'id' is used to identify the frame
        id = self.udi[0:HEADER_ID_SIZE]       # truncate udi to 6 octets
        # the protected additional data is just the id
        ad = [id]
        
        # the encrypted portion of the frame ------------------
        # 'rt' is the replay protection value of the transmitter
        rt = self.my_replay_value
        # 'rr' is the peer's anticipated value
        rr = self.peer_replay_value
        
        # concatenate the two replay values and message data
        frame_data = rt + rr + message_data
        
        # encrypt the message data, 'siv' field is prepended
        # by the encrytion process
        cipher_text = siv_encrypt(self._uds, frame_data, ad)

        # count frames transmitted with the same 'rt' and
        # change to new value after REPLAY_VALUE_LIFETIME transmissions
        self.transmitted_frame_count += 1
        if self.transmitted_frame_count > REPLAY_VALUE_LIFETIME:
            if self.my_replay_value_state == ECHOED:
                # normal path, prior value has been echoed by peer
                # it's ok to change to a new value
                self.change_my_replay_value()
        
        # concatenation of id and encrypted portion of the frame
        return id + cipher_text

    def decrypt_frame(self, encrypted_frame):
        """ Decrypt a frame.
        """
        id = encrypted_frame[0:HEADER_ID_SIZE]
        cipher_text = encrypted_frame[HEADER_ID_SIZE:]
        
        # check if 'id; is correct for link
        # note - AD maintains two links, for simplicity this is not shown
        # AD also supports a pairing discovery mode. In pairing
        # discovery the frame is not rejected, but used to discover
        # the peer's UDI and retrieve the UDS from the Key Dispenser (KD)
        # This is not yet shown and code only represents Operational link
        if id != self.udi[0:HEADER_ID_SIZE]:
            # reject the frame
            raise Exception("Wrong id on frame, not for this device")
        
        # decrypt the frame using the 'id' as an authenticated attribute
        # the SIV mode extracts the siv and raises an exception on
        # any integrity check failure
        plain_text = siv_decrypt(self._uds, cipher_text, [id] )
        
        # parse fields in decrypted frame
        rt = plain_text[0:REPLAY_VALUE_SIZE]    # peer transmitted replay protection value
        rr = plain_text[REPLAY_VALUE_SIZE:2*REPLAY_VALUE_SIZE] # echo of self's value
        message_data = plain_text[2*REPLAY_VALUE_SIZE:]
        
        # validate if replay values are correct
        if rr == self.my_replay_value:
            # correct echoed 'rr' for syncronized operational link
            # if this is the first time recived change state
            if self.my_replay_value_state == NEW:
                self.my_replay_value_state = ECHOED
            
            if rt == self.peer_replay_value:
                # expected peer value - normal operation
                return message_data
            else:
                # change in peer replay value
                # adopt new value and echo on subsequent transmissions
                self.peer_replay_value = rt
                return message_data
        elif rr == ZERO_REPLAY_FIELD:
            # peer has reset so adopt the new rt value
            self.peer_replay_value = rt
            # creat new local replay value
            self.my_replay_value = os.urandom(REPLAY_VALUE_SIZE)
            # reset the transmitted frame count (actually count for a replay value)
            self.transmitted_frame_count = 0
            # note any message_data sent in a reset frame (rr==0's) is subject to a
            # replay attack and should be restricted to static link setup information
            return message_data
        else:    # possible replay attack
            # on replay errors the frame is dropped by rasing an exception
            raise Exception("Bad peer replay value - likely replay attack")

    def change_my_replay_value(self):
        """ Function to change my_replay_value
            This can be random, psuedo random or just an incremented counter.
            Random provides better replay protection by ensuring that
            a captured stream that may be replayed (vary rare) will
            not be viable after the change.
        """
        # change value and ensure it is not randomly set to all zeros
        self.my_replay_value = ZERO_REPLAY_FIELD
        while self.my_replay_value == ZERO_REPLAY_FIELD:
            self.my_replay_value = os.urandom(REPLAY_VALUE_SIZE)
        
        # reset count of frames transmitted with the same value
        self.transmitted_frame_count = 0
        
        # reset the replay value state
        self.my_replay_value_state = NEW

def id_hash(uds):
    """ The hash function used the generate an identifier from
        the secret key.
        """
    # sha256 for testing now, Blake2b would be much smaller and faster
    return sha256(uds).digest()[0:UDI_SIZE]   # first 16 octets / 128 bits

# ----------------------------------------------------------
# Code for design validation and not specific to link algorithm
# remove later to different module
#
state_decode = {1:"NEW   ", 2:"ECHOED"}

class CL(ULPLinkProto):
    """ Class to simulate a single ULPD """
    def __init__(self, uds):
        """ The simulated creation of a ULPD """
        self._uds = uds
        self.udi = id_hash(self._uds)
        self.reset()

    def send(self, message_data):
        """ Encrypt verbose replay value output for design validation """
        frame = self.encrypt_frame( message_data )
        print "cl.send", b2a_hex(frame)
        clrt = b2a_hex(self.my_replay_value)
        clrr = b2a_hex(self.peer_replay_value)
        state = state_decode[self.my_replay_value_state]
        print("{} {} {} cl-->".format(state, clrt, clrr))
        return frame

    def recieve(self, frame):
        """ Decrypt verbose replay value output for design validation """
        message_data = self.decrypt_frame( frame )
        clrt = b2a_hex(self.my_replay_value)
        clrr = b2a_hex(self.peer_replay_value)
        state = state_decode[self.my_replay_value_state]
        print("{} {} {} cl<--".format(state, clrt, clrr))
        return message_data


class AD(ULPLinkProto):
    def __init__(self, ulpd):
        """ Simulation of a single session of a paired AD
            AD is passed a particular ULPD instance to simulate
            pairing process to access the unique device secret (uds)
        """
        self._uds = ulpd._uds
        self.udi = ulpd.udi
        self.reset()

    def send(self, message_data):
        """ Encrypt verbose replay value output for design validation """
        frame = self.encrypt_frame( message_data )
        adrt = b2a_hex(self.my_replay_value)
        adrr = b2a_hex(self.peer_replay_value)
        state = state_decode[self.my_replay_value_state]
        print("{} {} {}    <--ad {} {} {} ".format(6*' ',8*' ',8*' ',state, adrt, adrr))
        return frame

    def recieve(self, frame):
        """ Decrypt verbose replay value output for design validation """
        message_data = self.decrypt_frame( frame )
        adrt = b2a_hex(self.my_replay_value)
        adrr = b2a_hex(self.peer_replay_value)
        state = state_decode[self.my_replay_value_state]
        print("{} {} {}    -->ad {} {} {} ".format(6*' ',8*' ',8*' ',state, adrt, adrr))
        return message_data

# ---
uds = uds = 'fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'.decode('hex')
class Paired_Link:
    """ A class to simulate a paired link and display replay
        values for design validation.
    """
    def __init__(self, key=uds):
        """ Setup a pair of devices """
        self.cl = CL(uds)
        self.ad = AD(self.cl) # ad paired to cl

    def cl_to_ad(self, message_data):
        """ CL-to-AD Transmssion """
        frame = self.cl.send(message_data)           # processes and displays cl state
        ad_message_data = self.ad.recieve(frame) # processes and displays ad state
        assert message_data == ad_message_data  # validate correct encrypt/decrypt

    def ad_to_cl(self, message_data):
        """ AD-to-CL Transmssion """
        frame = self.ad.send(message_data)           # processes and displays cl state
        cl_message_data = self.cl.recieve(frame) # processes and displays ad state
        assert message_data == cl_message_data
    
    def cl_to_ad_dropped(self, message_data): pass
    def ad_to_cl_dropped(self, message_data): pass



def main():
    """ Design Validation """

    link = Paired_Link( key=uds )
    message_data = 10*'\FA'  # dummy data for testing

    link.cl_to_ad( message_data ) # send and recieve frame
    link.ad_to_cl( message_data )





if __name__ == '__main__':
    main()
