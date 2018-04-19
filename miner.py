import urllib2
import json
from hashlib import sha256 as H
from Crypto.Cipher import AES
from Crypto.Random import random
import time
from struct import pack, unpack
import requests
from multiprocessing import Pool, Process
from functools import partial
from scipy.spatial.distance import hamming


NODE_URL = "http://6857coin.csail.mit.edu"
MOD = 2 ** 128
NCORES = 4
BLOCK_CONTENTS = "eforde,qpm3,moezinia"
min_hd = 128

"""
    This is a bare-bones miner compatible with 6857coin, minus the final proof of
    work check. We have left lots of opportunities for optimization. Partial
    credit will be awarded for successfully mining any block that appends to
    a tree rooted at the genesis block. Full credit will be awarded for mining
    a block that adds to the main chain. Note that the faster you solve the proof
    of work, the better your chances are of landing in the main chain.

    Feel free to modify this code in any way, or reimplement it in a different
    language or on specialized hardware.

    Good luck!
"""


def solve_block(b, core):
    """
    Iterate over random nonce triples until a valid proof of work is found
    for the block

    Expects a block dictionary `b` with difficulty, version, parentid,
    timestamp, and root (a hash of the block data).

    """
    global min_hd

    d = b["difficulty"]
    dif = 128 - d
    print "Looking for hd less than", dif
    while True:
        b["nonces"] = [rand_nonce(64), rand_nonce(64), rand_nonce(64)]
        #   Compute Ai, Aj, Bi, Bj
        ciphers = compute_ciphers(b)
        #   Parse the ciphers as big-endian unsigned integers
        Ai, Aj, Bi, Bj = [unpack_uint128(cipher) for cipher in ciphers]
        # Verify PoW
        bytes1 = (Ai + Bj) % MOD
        bytes2 = (Aj + Bi) % MOD # type LONG


        # xor = bytes1 ^ bytes2
        # print((bytes1), "wenger out")
        # hd = hamming(list(bytes1), list(bytes2)) * len(bytes1)
        hd = hamming2(bin(bytes1), bin(bytes2))
        # print(hd, "wenger in")
        # hd = bin(xor).count('1')
        if hd < min_hd:
            min_hd = hd
            print core, "- New min hd:", min_hd
            if hd <= dif:
                print "Found nonces with hd", hd
                print b["nonces"]
                return


def hamming2(x, y):
    """Calculate the Hamming distance between two bit strings"""
    # assert len(x) == len(y)
    count,z = 0,int(x,2)^int(y,2)
    while z:
        count += 1
        z &= z-1 # magic!
    return count



def make_block():
    """
    Constructs a block dictionary from /next header information with
    our usernames as the contents
    """
    next_header = get_next()
    #   Next block's parent, version, difficulty
    #   Construct a block with our name in the contents that appends to the
    #   head of the main chain
    block = {
        "version": next_header["version"],
        #   for now, root is hash of block contents (team name)
        "root": hash_to_hex(BLOCK_CONTENTS),
        "parentid": next_header["parentid"],
        #   nanoseconds since unix epoch
        "timestamp": long(time.time()*1000*1000*1000),
        "difficulty": next_header["difficulty"]
    }
    return block

def main():
    global min_hd

    while True:
        # Try mining for 60 seconds on each core, then reload
        # in case a new block has been added
        min_hd = 128
        p = Process(target=spawn_miners)
        p.start()
        p.join(60)

def spawn_miners():
    block = make_block()
    print "\nSolving block..."
    print block
    pool = Pool()
    block_args = [(block.copy(), i) for i in xrange(NCORES)]
    results = pool.map_async(try_mine_block, block_args)
    pool.close()
    pool.join()
    print results.get()


def try_mine_block((new_block, core)):
    solve_block(new_block, core)
    #   Send to the server
    print core, "- Solved block."
    add_block(new_block, BLOCK_CONTENTS)
    return "SUCCESS"


def get_next():
    """
       Parse JSON of the next block info
           difficulty      uint64
           parentid        HexString
           version         single byte
    """
    return json.loads(urllib2.urlopen(NODE_URL + "/next").read())


def add_block(h, contents):
    """
       Send JSON of solved block to server.
       Note that the header and block contents are separated.
            header:
                difficulty      uint64
                parentid        HexString
                root            HexString
                timestampe      uint64
                version         single byte
            block:          string
    """
    add_block_request = {"header": h, "block": contents}
    print "Sending block to server..."
    print json.dumps(add_block_request)
    r = requests.post(NODE_URL + "/add", data=json.dumps(add_block_request))
    print r.status_code, r.content


def hash_block_to_hex(b):
    """
    Computes the hex-encoded hash of a block header. First builds an array of
    bytes with the correct endianness and length for each arguments. Then hashes
    the concatenation of these bytes and encodes to hexidecimal.

    Not used for mining since it includes all 3 nonces, but serves as the unique
    identifier for a block when querying the explorer.
    """
    packed_data = []
    packed_data.extend(b["parentid"].decode('hex'))
    packed_data.extend(b["root"].decode('hex'))
    packed_data.extend(pack('>Q', long(b["difficulty"])))
    packed_data.extend(pack('>Q', long(b["timestamp"])))
    #   Bigendian 64bit unsigned
    for n in b["nonces"]:
        #   Bigendian 64bit unsigned
        packed_data.extend(pack('>Q', long(n)))
    packed_data.append(chr(b["version"]))
    if len(packed_data) != 105:
        print "invalid length of packed data"
    h = H()
    h.update(''.join(packed_data))
    b["hash"] = h.digest().encode('hex')
    return b["hash"]


def compute_ciphers(b):
    """
    Computes the ciphers Ai, Aj, Bi, Bj of a block header.
    """

    packed_data = []
    packed_data.extend(b["parentid"].decode('hex'))
    packed_data.extend(b["root"].decode('hex'))
    packed_data.extend(pack('>Q', long(b["difficulty"])))
    packed_data.extend(pack('>Q', long(b["timestamp"])))
    packed_data.extend(pack('>Q', long(b["nonces"][0])))
    packed_data.append(chr(b["version"]))
    if len(packed_data) != 89:
        print "invalid length of packed data"
    h = H()
    h.update(''.join(packed_data))
    seed = h.digest()

    if len(seed) != 32:
        print "invalid length of packed data"
    h = H()
    h.update(seed)
    seed2 = h.digest()

    A = AES.new(seed, AES.MODE_ECB) # obj = AES.new('Thisisakey123456', AES.MODE_ECB)
    B = AES.new(seed2, AES.MODE_ECB)

    i = pack('>QQ', 0, long(b["nonces"][1]))
    j = pack('>QQ', 0, long(b["nonces"][2]))

    Ai = A.encrypt(i)
    Aj = A.encrypt(j)
    Bi = B.encrypt(i)
    Bj = B.encrypt(j)

    return Ai, Aj, Bi, Bj


def unpack_uint128(x):
    h, l = unpack('>QQ', x)
    return (h << 64) + l


def hash_to_hex(data):
    """Returns the hex-encoded hash of a byte string."""
    h = H()
    h.update(data)
    return h.digest().encode('hex')


def rand_nonce(n):
    """
    Returns a random uint64
    """
    return random.getrandbits(n)


if __name__ == "__main__":
    main()
