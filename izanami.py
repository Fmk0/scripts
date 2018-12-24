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
     r += chr(ord(c) ^ ord( k[i % len(cc)] ) )
   
  return r

     
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
  blob = blob.split('42590000525500000000000010000000')[-1]
  blob = blob.split('3a5a6f6e652e4964656e7469')[0]


  
  blob = list(filter(None, re.split(r'[0]{2,}', blob)))

  if len(blob) != 6:
    pos_version = -2
    pos_profile = -1
  else:
    pos_version = -1
    pos_profile = -2

  blob = blob[:4]

  for i, b in enumerate(blob):
     blob[i] = hotfix(b)

  # Key in hex
  key = str(blob[0])

  # C2
  c2 = xor_strings(unhexlify(blob[0]).decode(),unhexlify(blob[1]).decode())

  # Version
  version = unhexlify(blob[pos_version]).decode()
  profile = unhexlify(blob[pos_profile]).decode()
  
  if re.match('\d{2,}',version) and profile == "X":
    version = profile
    profile = unhexlify(blob[pos_version]).decode()

  # Profile
  if profile == 'X':
    profile += ' (default config -> 1)'

  if version == 'X':
    version += ' (Unknown)'

  print("Extracted config : \n> Key - {} \n> C2 - {} \n> Version - {} \n> Profile ID - {}".format(key, \
                    c2, \
                    version, \
                    profile))

def search(folder):
    for file in os.listdir(folder):
        print('----------------\nFile -> {}'.format(file))
        try:
           extract(os.path.join(folder, file))
        except:
           print('ERROR - Not a valid unpacked Vidar sample')

def usage():
    """ Program usage"""
    parser = argparse.ArgumentParser(prog="izanami")
    parser.add_argument('--extract','-e', dest='extract', \
                         help='extract config of a Vidar sample')
    parser.add_argument('--list','-l', dest='list', \
                         help='extract all configs from a selected repository')

    return parser.parse_args()


def main(args):  
    if args.extract:
       extract(args.extract)
   
    if args.list:
       search(args.list)

if  __name__ == '__main__':
    args = usage()
    main(args)

