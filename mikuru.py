import os
import re
import sys
import copy
import pype32
import pefile
import base64
from PIL import Image

"""
Dirty Static Unpacker for Adderall Protector

Well yes it's python2, i don't find any solution currently for a python3 version :'(
Thx @Snames for his awesome works on pype32 for the .NET implemenation.
"""

def create_directory(name):
    if not os.path.exists(name):
        os.makedirs(name)

def to_bytes(n, length):
    h = '%x' % n
    s = ('0'*(len(h) % 2) + h).zfill(length*2).decode('hex')
    return s

def decode_manifest(file,folder):
    b64 = re.compile('[a-zA-Z0-9+=/]+')
    tokens = b64.findall(file)
    manifest = []

    for i, t in enumerate(tokens):
        try:
            manifest.append(str(i) + " - " + base64.b64decode(str(t).strip()).decode('utf-8'))
        except:
            if i == 0 and len(t) == 1:
                return False

    with open(folder + '/manifest_decoded.log', 'w') as f:
        for m in manifest:
            f.write("%s\n" % m)

    return True

def extract_net_resource(pe,folder):
    resources = []

    pe = pype32.PE(folder + '/' + pe)
    m = pe.ntHeaders.optionalHeader.dataDirectory[14].info
    for i in m.directory.resources.info:
        data = pe.getDataAtRva(m.directory.resources.rva.value + i['offset'], i['size'])
        state = decode_manifest(data,folder)

        if state == False:
            with open(folder + '/' + i["name"], "wb") as f:
                 f.write(data)

    return resources

def extract_image(pe):
    pe = pefile.PE(pe)

    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if hasattr(entry, 'directory'):
            resource_type = pefile.RESOURCE_TYPE.get(entry.struct.Id)
            if resource_type == "RT_HTML":
                for directory in entry.directory.entries:
                    if hasattr(directory, 'directory'):
                        resource = directory.directory.entries[0]
                        data_rva = resource.data.struct.OffsetToData
                        size = resource.data.struct.Size
                        data = pe.get_memory_mapped_image()[data_rva:data_rva+size]

    with open("Stage 2/RT_HTML", "wb") as f:
        f.write(data)

def check_png(img):
    try:
        data = Image.open(img)
    except:
        print 'Not a valid image...'
        exit(1)

    return data

def switch_pos(n,l):
    # Gomennasai python dev gods :'(

    r = n / l
    return ((l -1) - (n % l)) + r * l

def dirty_hotfix(payload):
    ### Yes... This is garbage :cry:

    tmp = copy.deepcopy(payload)
    for i in range(0,len(payload) - ((len(payload) % 4))):
        payload[i] = tmp[switch_pos(i,4)]

    for i in range(len(payload) - ((len(payload) % 4)),len(payload)):
        payload[i] = tmp[switch_pos(i,(len(payload) % 4))]

    return payload

def unxor(payload):
    ### Get the XOR Key
    payload = bytearray(payload)
    key = bytearray(payload[0x20:0x30])

    ### Decrypting
    for i in range(0,len(payload)):
        payload[i] ^= key[i % 16]

    if payload[0:2] != "MZ":
         payload = dirty_hotfix(payload)

    return payload

def RGBbyte(rgb):
    """
      Goal  : Converting RGB Pixel to Int32 value in bytes
      Entry : Pixel value
      Return : 4 bytes format value of the selected pixel
    """

    r,g,b,a = rgb
    value = (a << 0x18) + (r << 0x10) + (g << 0x8) + b

    ## recreating the .NET integer overflow if its above the Int32 limit
    # if value > 0x7FFFFFFF:
    #    value %= 0x7FFFFFFF - 0x7FFFFFFF + 2

    return to_bytes(value,4)

def stage_2():
    ### Step 0 - Extracting PNG File
    create_directory("Stage 2")
    extract_image(sys.argv[1])

    print(">>> Stage 2 Extracted")

def stage_3():
    ### Step 1 - Loading png file
    fake_png = check_png("Stage 2/RT_HTML")

    ### Step 2 - Get the RGB Value of each pixel on an array
    payload = []
    width, height = fake_png.size
    for x in range(0,width):
        for y in range(0,height):
            payload += RGBbyte(fake_png.getpixel((x,y)))

    ### Step 3 - Deleting the first 4 junk bytes
    payload = payload[4:]

    ### Step 4 - Decrypting
    payload = unxor(payload)

    create_directory("Stage 3")

    with open('Stage 3/stage_3.bin','wb') as my_bin:
        my_bin.write(bytes(payload))

    extract_net_resource('stage_3.bin','Stage 3')

    print ">>> Stage 3 Unpacked..."


def stage_4():
    files = os.listdir('Stage 3')
    whitelist = ['manifest_decoded.log','stage_3.bin']

    create_directory("Stage 4")

    for f in files:
        if f not in whitelist:
            with open('Stage 3/' + f,'rb') as blob:
                payload = unxor(blob.read())

            with open('Stage 4/' + f,'wb') as blob:
                blob.write(payload)

    print ">>> Stage 4 Unpacked..."

def main():



    print " _____ _ _               "
    print "|     |_| |_ _ _ ___ _ _ "
    print "| | | | | '_| | |  _| | |"
    print "|_|_|_|_|_,_|___|_| |___|\n"


    stage_2()
    stage_3()
    stage_4()

    print "\nStage 3 & 4 are using DotWall protector for obfuscating .NET Payloads"
    print "Please use Dot4net and Dotwall Unpacker tools on github for digging more into them"
    print "Happy Hunting o/"

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "COMMAND> {} <packed_payload>".format(sys.argv[0])
    else:
        main()
