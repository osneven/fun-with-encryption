'''

NHash, a dynamic hash algorithm
Author: Oliver Stochholm Neven

'''

import math, time, os

TITLE = 'NHash'
VERSION = 1.0

# The fist 32 primes which power of 23 is grater than or equal to 32 bytes in size.
HASH_TABLE = [
0x111bf2933cedaeadf955725600d1cadcf498f03e1f55e53e7dbe25c0f5e38439,
0x11eaa8eb317e7c2dcd851919d29e59467310f67f39c2390c8843c4399dd574e5,
0x12557bcdaf5ac22a96f15b12a34aee3ba1bfeaa90a5b2bae57c89c9003533eaf,
0x1332504da28ec2dbd3892fb35c1c618a8965be2b573e6cfa6ba5dfc6b847837b,
0x150a2719831f7ab83ccd98b2b67f096ba2d4ed3203e84ae886e3b125916edc33,
0x168826ec5d87db3c34351cd6ba208ee34541d9c095615f4543211835e1652921,
0x1795120febc5680132f459ff32d5fc5e2d4950b53583e495d2755bcf0391100d,
0x193f0bd3ed863093bc4abcedf7ca7eac254878341118d07da836f644c1329023,
0x19d351b3be6f099440295a557204442f000e4397ec4ba41c2aa9b56fbec3d4c5,
0x1cead21c97398839f7b5cb4b45d996ae0f59858244151534760161ed15253207,
0x21d891366963319216f4eaaa9f3e58c360b812d159a5455558a5735990c30ded,
0x25d918b8240baf78914cb669de0ac108b865254bebbb9d02ed06020075b26c6f,
0x287664408d801c060e82d014898c6c34f7396a422cf56832b3258c99aba05fdd,
0x2e38050d9e75232172cc7eba45bdebee718f09cc5d7b8b18879900f2a0442ee1,
0x2f4058ec5441332bb0a9d82c1b382c940513202476bda0df48d1d7476571442b,
0x31620bcc34a5208c36addec8833041cd455d65463be3295b68bb2e9328f19c57,
0x327ba63064c736cb328f01ef2f07da4d813d24e988b6fd9bfe24feb25b9bd6d9,
0x38580c0671e023b7d951063219228386ae95e9a6787307664dec1094a1c87b1b,
0x403cde5a33e7d2f62943312531ff6ed2f62dba64ffce43dd9bb8c0ea71e8edbf,
0x41a6f8cb9b7700e6096770c15f3f529450fe9fffb3d370a6ff882e7726708dc1,
0x4e174f5c399026476f0b8dc5d5dc94f1cbbfd1dd48a6352c98adcb8677156431,
0x4fcbbe312f2147ec77cdecc60ae244527f8b3c717017baa2032b715201f392fb,
0x5520664100028410a62f9d8939e2076da157e10b55cf8488974501ef62cfb729,
0x58de280fef9d21613179503db15a5c913b80df4fca85f22a4844b9596318eb55,
0x5acc017a41859cc5cc5f2d6f1c992cb3cb307d919caea5fdf8ec53e3e2c3ac9f,
0x650f07c975e3100a9556fe9ce6cda6e97cdbddee7ea2fef37186a90b33c18099,
0x6e0eca1827bba3881f3e5b82ac67da57476b94e1e773793d614ed60920d8ff11,
0x8531177328e0d639d0e694c683d6edf09db26b22ce4861ec045dfa4253e7bfcb,
0xab5aa68b3377d3a90dc6d50d174a4132551aa51ca32eb82ef80af38cd3ed8773,
0xb2a7a24afdea7cc246f5e6e13ba3ef7beefc43cabfefddf5d2b49e3e198b725f,
0xb66a744bfcdbbc9b96bbf58b7ae788bbff979ca44c7fa532aeebc56de1751a61,
0xbe2a93c18d5adad2973515f21bec881f9dac0e543e5e6b9a2972835d11407b4d,
0xce9f65d38fa628a7498b5b5695918e5b195828f8a08066713eb47f7455e2fc05,
]

# Converts a bytes like object to an integer
def bytes_to_int(bytes_to_convert):
	string_to_return = ''
	# Go through every byte and append its hexadecimal value to the string
	for byte in bytes_to_convert:
		hex_of_bytes = hex(byte)[2:]
		string_to_return += '0'*(2-len(hex_of_bytes)) + hex_of_bytes
	return int(string_to_return, 16) # Return the string as an integer

# Converts an integer to a bytes like object
def int_to_bytes(int_to_convert):
	bytes_to_return = b''
	# Convert the integer to a hexadecimal
	hex_to_convert = hex(int_to_convert)[2:]
	# Append a zero to the begging of the hexadecimal if its length is not divisible by two
	if len(hex_to_convert)%2 == 1: hex_to_convert = '0' + hex_to_convert
	# Go through every byte of the hexadecimal (every two decimals) and appends its bytes value to the other ones
	for i in range(0, len(hex_to_convert), 2): bytes_to_return += bytes([int(hex_to_convert[i:i+2], 16)])
	return bytes_to_return

# Append a padding to the end of the bytes like object
def append_bytes_padding(bytes_to_pad, length):
	rest = int(length - len(bytes_to_pad) % length)
	if rest != length: bytes_to_pad += bytes_to_pad[-1:] * rest
	return bytes_to_pad

# Hashes a bytes like object
def hash_bytes(bytes_to_hash, length):
	# Make sure its length is divisible by 32, do this by simple appending a padding
	bytes_to_hash = append_bytes_padding(bytes_to_hash, length)

	# Split bytes into chunks of 32 bytes
	byte_chunks = []
	[ byte_chunks.append(bytes_to_hash[i:i+32]) for i in range(0, len(bytes_to_hash), 32) ]

	# STAGE 1: xor each 32 byte chunk with the hash table
	hashed_bytes = b''
	for byte in byte_chunks:
		hashed_bytes += xor_32_bytes_with_hash_table(byte)

	# STAGE 2: xor each 32 byte chunk together
	hashed_bytes = xor_bytes_together(hashed_bytes, length/8)







	#print(len(bytes_to_hash), hex(bytes_to_int(bytes_to_hash)))
	print()
	print(bytes_to_int(hashed_bytes).bit_length(), hex(bytes_to_int(hashed_bytes)))

# xor's 32 bytes of data together with the hash table
def xor_32_bytes_with_hash_table(bytes_to_hash):
	int_to_hash = bytes_to_int(bytes_to_hash)
	#print(hex(int_to_hash), '->') ##### FOR DEBUG
	hashed_int = HASH_TABLE[(int_to_hash*int_to_hash.bit_length())%len(HASH_TABLE)]^int_to_hash
	#print(hex(hashed_int), '\n') ##### FOR DEBUG
	return int_to_bytes(hashed_int)

# xor's bytes together and returns a bytes like object with a specific length
def xor_bytes_together(bytes_to_hash, length):
	hashed_integer = 0
	hex_to_hash = hex(bytes_to_int(bytes_to_hash))[2:]
	for i in range(0, len(hex_to_hash), 32):
		hashed_integer ^= int(append_bytes_padding(hex_to_hash[i:i + 32], length), 16)
	bytes_to_hash = int_to_bytes(hashed_integer)
	hashed_bytes = b''
	for i in range(0, len(bytes_to_hash), 32):
		hashed_bytes += xor_32_bytes_with_hash_table(bytes_to_hash[i:i + 32])
	return hashed_bytes

#digest = hash_bytes(os.urandom(128), 150)
digest = hash_bytes(b'hell:o', 64)


