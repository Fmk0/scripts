'''
    - Shiina -
    Steganography / PE Analyzer Tool
'''

_VER_ = "0.2"

import os
import sys
import binascii
import argparse
from PIL import Image

def ran(i):
    return os.urandom(i*i)

def hex2rgb(h):
    h = h.decode()
    while len(h) % 3 != 0:
        h += "00"
    return tuple(int(h[i:i+2],16) for i in (0,2,4))

def generate(payload):
    with open(payload,'rb') as myBlob:
        blob = myBlob.read()

    i = 1
    while i*i < len(blob)/3:
        i+=1

    print('Selected size for this payload -> {}x{}'.format(i,i))
    print('Pixels required for storing the payload -> {}'.format(len(blob)//3 + (len(blob) % 3 > 0)))

    im = Image.new('RGB',(i,i),"black")
    fake = im.load()

    for c, j in enumerate(range(0,len(blob),3)):
        fake[c / i,c % i] = hex2rgb(binascii.hexlify(blob[j:j+3]))

    im.save('img.png','PNG')

def RGBbyte(rgb):
    r,g,b = rgb
    v = (r << 0x10) + (g << 0x8) + b
    return v.to_bytes(3,byteorder='big')

def extract(fake_png):
    try:
       im = Image.open(fake_png)
    except:
       print('ERROR: Not a valid image')
       exit(1)

    payload = []
    width, height = im.size
    for x in range(0,width):
        for y in range(0,height):
            payload += RGBbyte(im.getpixel((x,y)))

    with open('payload_unpacked.exe','wb') as myBlob:
         myBlob.write(bytes(payload))

    print('Payload extracted !\n')

def logo():
    print('   _____ __    _ _            ')
    print('  / ___// /_  (_|_)___  ____ _')
    print('  \__ \/ __ \/ / / __ \/ __ `/')
    print(' ___/ / / / / / / / / / /_/ / ')
    print('/____/_/ /_/_/_/_/ /_/\__,_/ v{}\n'.format(_VER_))

parser = argparse.ArgumentParser()
parser.add_argument("-g", "--generate", nargs=1,
                    help="generate a PNG image")
parser.add_argument("-e","--extract", nargs=1,
                    help="extract payload from fake PNG image")
args = parser.parse_args()

logo()

if args.generate:
    generate(args.generate[0])
elif args.extract:
    extract(args.extract[0])
