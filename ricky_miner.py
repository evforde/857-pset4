import urllib2
import json
from hashlib import sha256 as H
from Crypto.Cipher import AES
from Crypto.Random import random
import time
from struct import pack, unpack
import requests
from scipy.spatial.distance import hamming

NODE_URL = "http://6857coin.csail.mit.edu"

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


def solve_block(b):
    """
    Iterate over random nonce triples until a valid proof of work is found
    for the block

    Expects a block dictionary `b` with difficulty, version, parentid,
    timestamp, and root (a hash of the block data).

    """
    d = b["difficulty"]
    max_hd = 128-d
    MOD = 2**128
    while True:
        b["nonces"] = [rand_nonce() for i in range(3)]
        #   Compute Ai, Aj, Bi, Bj
        ciphers = compute_ciphers(b)
        #   Parse the ciphers as big-endian unsigned integers
        Ai, Aj, Bi, Bj = [unpack_uint128(cipher) for cipher in ciphers]
        #   TODO: Verify PoW
        # these are unpacked AES outputs (ciphers) of using nonces as message and key of AES as hash of the bocks
        i, j = b["nonces"][1], b["nonces"][2]
        if i != j:
            bytes1 = (Ai + Bj) % MOD
            bytes2 = (Aj + Bi) % MOD
            hd = hamming(bytes1, bytes2)
            if hd < max_hd:
                return


# {
#   "id": "b06d3cd2b82f675bb393b6364eb5180a0a694d6d8c57f909447d0345ea856964",
#   "header": {
#     "parentid": "158cb88bce624030e00081e3e85a19fe7fa9c6f748dae3a5ed7928c511f767d5",
#     "root": "7b538882be8aaf30b5b5edb11500cdbd78dd44804b12d7dff1f9e794b8a5350f",
#     "difficulty": 108,
#     "timestamp": 1522944534840954185,
#     "nonces": [
#       441507584051665729,
#       2314080862,
#       2685329542
#     ],
#     "version": 0
#   },
#   "block": "andrewhe,baula,werryju",
#   "blockheight": 2017,
#   "ismainchain": true,
#   "evermainchain": true,
#   "totaldiff": 194904,
#   "timestamp": "2018-04-05T16:08:54.840954185Z"
# }



def main():
    """
    Repeatedly request next block parameters from the server, then solve a block
    containing our team name.

    We will construct a block dictionary and pass this around to solving and
    submission functions.
    """
    block_contents = "eforde,qpm3,moezinia"

    while True:
        #   Next block's parent, version, difficulty
        next_header = get_next()
        #   Construct a block with our name in the contents that appends to the
        #   head of the main chain
        new_block = make_block(next_header, block_contents)
        #   Solve the POW
        print "Solving block..."
        print new_block
        solve_block(new_block)
        #   Send to the server
        add_block(new_block, block_contents)


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
    print r


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
    # big endian unsigned long, 64 bits
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

    A = AES.new(seed)
    B = AES.new(seed2)

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


def make_block(next_info, contents):
    """
    Constructs a block from /next header information `next_info` and sepcified
    contents.
    """
    block = {
        "version": next_info["version"],
        #   for now, root is hash of block contents (team name)
        "root": hash_to_hex(contents),
        "parentid": next_info["parentid"],
        #   nanoseconds since unix epoch
        "timestamp": long(time.time()*1000*1000*1000),
        "difficulty": next_info["difficulty"]
    }
    return block


def rand_nonce():
    """
    Returns a random uint64
    """
    return random.getrandbits(64)


if __name__ == "__main__":
    main()
