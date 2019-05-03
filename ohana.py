import re
import os
import argparse
from binascii import hexlify, unhexlify

def hotfix(b):
  if len(b) % 2:
    b += '0'
  return b

def xor_strings(k, cc):
  r = ""
  for i, c in enumerate(cc):
     r += chr(ord(c) ^ ord( k[i % len(k)] ) )
   
  return r

def invalid_array(a):
  for i in a:
    if len(i) != 8:
      return True

  return False

def extract(payload):
  try:
    with open(payload,'rb') as myBlob:
      blob = myBlob.read()
  except:
    print('Error : File not found')
    return

  if not blob.startswith(b'MZ'):
     print('Error : Not a PE')
     return

  #Searching position of the config setup
  blob = str(hexlify(blob))

  # Get encrypted & encoded strings
  raw = blob.split('73746f6920617267756d656e74206f7574206f662072616e6765')[-1]
  raw = raw.split('0030313233343536373839414243444546474849474b4c4d4e4f')[0]
  raw = list(filter(None, re.split(r'[0]{2,}', raw)))

  # Get XOR key
  xor_key = blob.split('004142434445464748494a4b4c4d4e4f505152535455565758595a00')[-1]
  xor_key = xor_key.split('000f00')[0].replace('ff','00')
  xor_key = list(filter(None, re.split(r'[0]{2,}', xor_key)))
  xor_key = [x.replace('010101','') for x in xor_key]

  for i, r in enumerate(raw):
     raw[i] = hotfix(r)
  
  while invalid_array(xor_key):
    for i, a in enumerate(xor_key):
      if len(a) != 8:
        xor_key.pop(i)
        break

  # Key in hex
  key = xor_key[0]

  # C2
  c2 = xor_strings(unhexlify(key).decode(),unhexlify(raw[0]).decode())

  # ???
  unknown = xor_strings(unhexlify(key).decode(),unhexlify(raw[-1]).decode())

  print("Extracted config : \n> Key - {} \n> C2 - {} \n> Loader - {} \n".format(key, c2, unknown))

def search(folder):
    for file in os.listdir(folder):
        print('----------------\nFile -> {}'.format(file))
        try:
           extract(os.path.join(folder, file))
        except:
           print('ERROR - Not a valid unpacked Megumin sample')

def usage():
    """ Program usage"""
    parser = argparse.ArgumentParser(prog="ohana")
    parser.add_argument('--extract','-e', dest='extract', \
                         help='extract config from a Megumin V2 Sample')
    parser.add_argument('--list','-l', dest='list', \
                         help='extract all configs from a selected repository')

    return parser.parse_args()


def main(args):
    print('   ____  __                     ')
    print('  / __ \/ /_  ____ _____  ____ _')
    print(' / / / / __ \/ __ `/ __ \/ __ `/')
    print('/ /_/ / / / / /_/ / / / / /_/ / ')
    print('\____/_/ /_/\__,_/_/ /_/\__,_/  \n')
                                


    if args.extract:
       extract(args.extract)
   
    if args.list:
       search(args.list)

if  __name__ == '__main__':
    args = usage()
    main(args)

