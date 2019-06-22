#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import binascii
import logging
import sys

from argparse import ArgumentParser
from Crypto.Cipher import AES

################################################################################
# Argument parser
################################################################################
def get_parser():
    """ Takes care of script argument parsing. """
    parser = ArgumentParser(description='Alert Alarm SMS xploiter')

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
    sms_dict["version"] = "{}".format(int(sms[0:1]))
    sms_dict["i"]       = "{}".format(int(sms[1:2]))
    sms_dict["j"]       = "{}".format(int(sms[2:3]))
    sms_dict["year"]    = "{:02d}".format(int(sms[3:5]))
    sms_dict["month"]   = "{}".format(hex(int(sms[5:6])))
    sms_dict["day"]     = "{:02d}".format(int(sms[6:8]))
    sms_dict["hour"]    = "{:02d}".format(int(sms[8:10]))
    sms_dict["minute"]  = "{:02d}".format(int(sms[10:12]))
    sms_dict["userid"]  = "{:02d}".format(int(sms[12:14]))

    return sms_dict


def decrypt(key, msg, iv):
    iv = hex_to_bytearray(iv)
    key = hex_to_bytearray(key)
    msg = hex_to_bytearray(msg)
    cipher_ctx = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher_ctx.decrypt(msg)
    logging.debug("Plaintext: {}".format(plaintext))
    return plaintext

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

    encrypt = True;

    if args.encrypt:
        logging.info("Mode: encryption");

    if args.decrypt:
        logging.info("Mode: decryption");
        encrypt = False;

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
        key_raw = "{}{}".format("000000000000", args.pin)
        key = string_to_hex(key_raw)
        logging.debug("Key: {} ({})".format(key, key_raw))
        if encrypt:
            logging.debug("TODO: Add encrypt")
        else:
            plaintext = decrypt(key, msg, iv)
            pt_dict = decoded_sms_to_dict(plaintext)
            pretty_print_sms_dict(pt_dict)

if __name__ == "__main__":
    main(sys.argv)
