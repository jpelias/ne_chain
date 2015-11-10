# -*- coding: utf-8 -*-

from bitcoin import * 
import pbkdf2
import unicodedata
import math
import string
import ecdsa
import requests
import json

# http://www.asahi-net.or.jp/~ax2s-kmtn/ref/unicode/e_asia.html
CJK_INTERVALS = [
    (0x4E00, 0x9FFF, 'CJK Unified Ideographs'),
    (0x3400, 0x4DBF, 'CJK Unified Ideographs Extension A'),
    (0x20000, 0x2A6DF, 'CJK Unified Ideographs Extension B'),
    (0x2A700, 0x2B73F, 'CJK Unified Ideographs Extension C'),
    (0x2B740, 0x2B81F, 'CJK Unified Ideographs Extension D'),
    (0xF900, 0xFAFF, 'CJK Compatibility Ideographs'),
    (0x2F800, 0x2FA1D, 'CJK Compatibility Ideographs Supplement'),
    (0x3190, 0x319F , 'Kanbun'),
    (0x2E80, 0x2EFF, 'CJK Radicals Supplement'),
    (0x2F00, 0x2FDF, 'CJK Radicals'),
    (0x31C0, 0x31EF, 'CJK Strokes'),
    (0x2FF0, 0x2FFF, 'Ideographic Description Characters'),
    (0xE0100, 0xE01EF, 'Variation Selectors Supplement'),
    (0x3100, 0x312F, 'Bopomofo'),
    (0x31A0, 0x31BF, 'Bopomofo Extended'),
    (0xFF00, 0xFFEF, 'Halfwidth and Fullwidth Forms'),
    (0x3040, 0x309F, 'Hiragana'),
    (0x30A0, 0x30FF, 'Katakana'),
    (0x31F0, 0x31FF, 'Katakana Phonetic Extensions'),
    (0x1B000, 0x1B0FF, 'Kana Supplement'),
    (0xAC00, 0xD7AF, 'Hangul Syllables'),
    (0x1100, 0x11FF, 'Hangul Jamo'),
    (0xA960, 0xA97F, 'Hangul Jamo Extended A'),
    (0xD7B0, 0xD7FF, 'Hangul Jamo Extended B'),
    (0x3130, 0x318F, 'Hangul Compatibility Jamo'),
    (0xA4D0, 0xA4FF, 'Lisu'),
    (0x16F00, 0x16F9F, 'Miao'),
    (0xA000, 0xA48F, 'Yi Syllables'),
    (0xA490, 0xA4CF, 'Yi Radicals'),
]

def is_CJK(c):
    n = ord(c)
    for imin,imax,name in CJK_INTERVALS:
        if n>=imin and n<=imax: return True
    return False
  
    
    
def electrumv2_extract_seed(words, password=''):
    """Takes Electrum v2.0 13 word mnemonic string and returns seed. Only works on English for now"""
    # clean-up unicode characters
    mnemonic = words[:]
    try:
        mnemonic = unicodedata.normalize('NFC', unicode(' '.join(words.lower().strip().split()))).encode('utf-8') # a string of 13 words
    except Exception as e:
        raise Exception(str(e))
    rootseed = pbkdf2.PBKDF2(str(mnemonic), str('electrum' + password), 2048,  macmodule=hmac, digestmodule=hashlib.sha512).read(64)
    return rootseed

def electrumv2_mnemonic_to_mprivkey(words, password=''):
    return bip32_master_key(electrumv2_extract_seed(words, password=''))

#################################################################

def mnemonic_encode(wordlist, i):
    n = len(wordlist)
    words = []
    while i:
        x = i%n
        i = i/n
        words.append(wordlist[x])
    return ' '.join(words)

def mnemonic_decode(wordlist, seed):
    n = len(wordlist)
    words = seed.split()
    i = 0
    while words:
        w = words.pop()
        k = wordlist.index(w)
        i = i*n + k
    return i

def is_new_seed(x, prefix='01'):
    hmac_sha_512 = lambda x,y: hmac.new(x, y, hashlib.sha512).digest()
    x = prepare_seed(x)
    s = hmac_sha_512("Seed version", x.encode('utf8')).encode('hex')
    return s.startswith(prefix)

def prepare_seed(seed):
    # normalize
    seed = unicodedata.normalize('NFKD', unicode(seed))
    # lower
    seed = seed.lower()
    # remove accents
    seed = u''.join([c for c in seed if not unicodedata.combining(c)])
    # normalize whitespaces
    seed = u' '.join(seed.split())
    # remove whitespaces between CJK
    seed = u''.join([seed[i] for i in range(len(seed)) if not (seed[i] in string.whitespace and is_CJK(seed[i-1]) and is_CJK(seed[i+1]))])
    return seed

s = open('english.txt','r').read().strip()
s = unicodedata.normalize('NFKD', s.decode('utf8'))
lines = s.split('\n')
wordlist = []
for line in lines:
    line = line.split('#')[0]
    line = line.strip(' \r')
    assert ' ' not in line
    if line:
        wordlist.append(line)
#print ("wordlist has %d words"%len(wordlist))


def mnemonic(wordlist):  
    num_bits = 128
    prefix = '01'
    custom_entropy = 1
    n = int(math.ceil(math.log(custom_entropy,2)))
    # bits of entropy used by the prefix
    k = len(prefix)*4
    # we add at least 16 bits
    n_added = max(16, k + num_bits - n)
    #print ("make_seed", prefix, "adding %d bits"%n_added)
    my_entropy = ecdsa.util.randrange( pow(2, n_added) )
    nonce = 0
    while True:
        nonce += 1
        i = custom_entropy * (my_entropy + nonce)
        seed = mnemonic_encode(wordlist, i)
        assert i == mnemonic_decode(wordlist, seed)
        #if is_old_seed(seed):
        #    continue
        if is_new_seed(seed, prefix):
            break
    return seed

for joder in range(2000000):
    
    def mnemonic(wordlist):  
        num_bits = 128
        prefix = '01'
        custom_entropy = 1
        n = int(math.ceil(math.log(custom_entropy,2)))
        # bits of entropy used by the prefix
        k = len(prefix)*4
        # we add at least 16 bits
        n_added = max(16, k + num_bits - n)
        #print ("make_seed", prefix, "adding %d bits"%n_added)
        my_entropy = ecdsa.util.randrange( pow(2, n_added) )
        nonce = 0
        while True:
            nonce += 1
            i = custom_entropy * (my_entropy + nonce)
            seed = mnemonic_encode(wordlist, i)
            assert i == mnemonic_decode(wordlist, seed)
            #if is_old_seed(seed):
            #    continue
            if is_new_seed(seed, prefix):
                break
        return seed


    mnemonic = mnemonic(wordlist) 

    print mnemonic

    xprb = electrumv2_mnemonic_to_mprivkey (mnemonic)

    privkey = encode_privkey (bip32_extract_key (bip32_ckd(bip32_ckd(xprb, 1), 1) ) ,'wif_compressed') 
      
    address = privtoaddr(privkey)

    url = "https://chain.so/api/v2/get_address_balance/BTC/" + address

    headers = {'Content-Type': 'application/json',
       'Accept-Encoding': 'gzip, deflate' ,
       'User-Agent': 'Ninguno' ,
       'Connection': 'keep-alive'}

    cantidad = 0

    r = requests.get(url,headers=headers)

    if r.status_code == 200:

        data=r.json()

        #print data

        cantidad = (float (data['data']['confirmed_balance']))

        print cantidad 

