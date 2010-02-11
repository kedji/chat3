#!/usr/bin/env ruby

# Copyright notice:
#  (C) 2009-2010
# This software is provided 'as-is' without any express or implied warranty.
# In no event will the authors be held liable for damages arising from the
# use of this software.  All license is reserved.


$LOAD_PATH.push File.dirname(__FILE__)
#### Aggregator included 'client3.rb' ####
# Copyright notice:
#  (C) 2009-2010
# This software is provided 'as-is' without any express or implied warranty.
# In no event will the authors be held liable for damages arising from the
# use of this software.  All license is reserved.


# Object that mediates access between the server and the local chat window.
# This object establishes connections, receives messages, and sends messages.
# Last revision:  December 3, 2009

#### Aggregator included 'comm3.rb' ####
# Copyright notice:
#  (C) 2009-2010
# This software is provided 'as-is' without any express or implied warranty.
# In no event will the authors be held liable for damages arising from the
# use of this software.  All license is reserved.


# Communication abstraction layer for Chat 3.0 - used by both the client and
# the server.
# Last revision:  Feb 9, 2009

# Find the file directory
fdir = (File.join(File.expand_path('~'), '.sechat') rescue '.')
fdir = ENV['CHAT30DIR'] if ENV['CHAT30DIR']
FILE_DIRECTORY = fdir

require 'socket'
require 'openssl'
require 'md5'
require 'monitor'

#### Aggregator included 'symmetric3.rb' ####
# Copyright notice:
#  (C) 2009-2010
# This software is provided 'as-is' without any express or implied warranty.
# In no event will the authors be held liable for damages arising from the
# use of this software.  All license is reserved.


# Third-generation symmetric encryption management system for Chat 3.0.
# Manages a "keyring" of symmetric keys and provides encryption/decryption
# using OpenSSL 256-bit AES with CBC.  No sourcecoding.
# Last revision:  December 5, 2009

require 'openssl'

# This class performs encryption and decryption, and manages one cipher object
# that maintains cryptographic state in a psuedo-connection.
class AES3

  # Encryption Constants
  ENC_TYPE          = 'AES-256-CBC'
  ENC_IV_TEMPLATE   = '_%016x'
  SALT_BYTES        = 8

  # Accessors
  attr_reader :key, :iv

  # Generate a new random AES key - 32 bytes, represented in hex
  def self.new_key
    "%064x" % (rand(2**256))
  end

  # Generate a new random IV (doubles as keyring ID) - 8 bytes, raw binary str
  def self.new_iv
    (1..8).inject('') { |s,_| s << rand(256).chr }
  end

  # Return the IV as a 64-bit number
  def self.iv_64(iv)
    return nil unless iv and iv.length == 8
    iv_num = 0 ; iv.each_byte { |b| iv_num = (iv_num << 8) + b }
    iv_num
  end

  # Return the IV in AES3 display format
  def self.iv_str(iv)
    return nil unless iv and iv.length == 8
    num = iv_64(iv)
    "%08x:%08x" % [ num >> 32, num & 0xFFFFFFFF ]
  end

  # Return the IV in AES3 format from display format
  def self.iv_from_str(ivstr)
    ivnum = ivstr.sub(':', '').to_i(16)
    iv = ''
    8.times { iv << (ivnum & 0xFF).chr ; ivnum >>= 8 }
    iv.reverse
  end

  # Generate a new AES Cipher object
  def initialize(aes_key, aes_iv)
    @key = aes_key
    @iv  = aes_iv
    iv_num = AES3::iv_64(aes_iv)

    # Set up out local decryption and encryption objects for AES
    @enc_aes = OpenSSL::Cipher::Cipher.new(ENC_TYPE)
    @enc_aes.encrypt
    @enc_aes.key = aes_key
    @enc_aes.iv = (ENC_IV_TEMPLATE % iv_num)
    @dec_aes = OpenSSL::Cipher::Cipher.new(ENC_TYPE)
    @dec_aes.decrypt
    @dec_aes.key = aes_key
    @dec_aes.iv = (ENC_IV_TEMPLATE % iv_num)
  end

  # Take a message of arbitrary length and encrypt it after salting it
  def encrypt(plaintext)
    salt = (1..SALT_BYTES).inject('') { |s,_| s << rand(256).chr }
    opaque = @enc_aes.update(plaintext + salt)
    opaque << @enc_aes.final
    @enc_aes.reset
    opaque
  end

  # Decrypt a message encoded with encrypt(), then de-salt it
  def decrypt(opaque)
    plaintext = @dec_aes.update(opaque)
    plaintext << @dec_aes.final
    @dec_aes.reset
    plaintext[-SALT_BYTES..-1] = ''
    plaintext
  end

end  # of AES3 class


# This class manages a "keyring" - a collection of encryption objects
# identified by a public, shared, 8-byte ID (randomly generated, also serves
# as the IV).  Messages can be encrypted or decrypted transparently by
# this container object so long as the key is held.  If the key is not held,
# an exception will be raised.
class Keyring

  attr_reader :ring, :default, :open_key

  # Start with a bootstrap default key, change this soon (frequent rekeying
  # is good for the soul!).  This will be used for all outgoing encryption
  # messages.
  def initialize()
    @ring = {}
    @open_key = AES3.new(
      "c18190c84fafdb21e8b08152549a7a02f59dfb005879afd1aba6cfbe039cb22e",
      "\xFEChat\x03.\x01")
    @ring[@open_key.iv] = @open_key
    @default = @open_key
  end

  # Decrypt a message, raise an exception if we don't hold the right key
  def decrypt(iv, opaque)
    cipher = @ring[iv]
    unless cipher
      raise "Key for #{AES3::iv_str(iv) || '<invalid IV>'} not found"
    end
    cipher.decrypt(opaque)
  end

  # Encrypt a message using the default key
  def encrypt(plaintext)
    @default.encrypt(plaintext)
  end
  
  # Encrypt a message using the open key (so everyone can read this)
  def open_encrypt(plaintext)
    @open_key.encrypt(plaintext)
  end

  # Add a key/IV to the keyring.  Do nothing on duplicate add.  Raise
  # exception on conflicting add.
  def add_key(iv, key)
    iv  = iv.to_s
    key = key.to_s
    raise "Invalid iv" unless iv.length == 8
    raise "Invalid AES key" unless key.length == 64
    if @ring[iv] and @ring[iv].key != key
      raise "Conflicting key for IV #{AES3::iv_str(iv)}"
    end
    @ring[iv] = AES3.new(key, iv) unless @ring[iv]
    nil
  end
  
  # Add a key and set it as our default (outgoing) key
  def rekey!
    iv = AES3::new_iv
    key = AES3::new_key
    add_key(iv, key)
    @default = @ring[iv]
    return [ iv, key ]
  end

  # Delete a key from our keyring
  def delete_key(iv)
    @ring.delete iv
  end

  # Return the number of keys in the keyring, including our own
  def length
    @ring.length
  end

end  # of class Keyring
#### End of aggregated 'symmetric3.rb' ####
#### Aggregator included 'rsa.rb' ####
#!/usr/local/bin/ruby -w

# Copyright notice:
#  (C) 2009-2010
# This software is provided 'as-is' without any express or implied warranty.
# In no event will the authors be held liable for damages arising from the
# use of this software.  All license is reserved.


# This is the class that holds and generates RSA keys, as well as performs
# encryption/decryption operations using those keys.  A key object contains
# one half of a key pair - either a private or a public key.
# Last revision:  March 3, 2008

class Key

  include Math

  attr_writer :keyv, :bits, :mod
  attr_reader :keyv, :bits, :mod

  # Constructor
  def initialize(keyString=nil)
    @keyv = nil
    @bits = nil
    @mod = nil
    self.key=(keyString)
  end

  # Key generator, returns two keys.  The bits parameter must be an even
  # multiple of 8.  Both of the returned keys can be used as either public
  # or private.  Optionally takes a suggested value of e which, if prime
  # will be used instead of a value calculated relative to phi.
  def Key.keygen(bits, suggested_e = nil)
    e, d, p, q = 0, 0, 0, 0

    # Fail if bits is not a multiple of 8
    raise "bits not divisible by 8" if bits < 8 or bits % 8 != 0
    bits += 4

    # Now generate our p and q
    while e == d
      while p == q
        p = Key.randomPrime(bits/2)
        q = Key.randomPrime(bits/2)
      end
      
      # Now generate our phi, modulus, e and d
      phi = (p-1) * (q-1)
      mod = p * q
      if suggested_e and fast_prime(suggested_e)
        e = suggested_e
      else
        e = Key.getEFromPhi(phi)
      end
      d = invmod(e, phi)
      p, q, phi = 0, 0, 0
    end
      
    # Construct the new key structures
    k1 = Key.new
    k2 = Key.new
    k1.keyv = e
    k2.keyv = d
    k1.bits = k2.bits = bits-4
    k1.mod = k2.mod = mod
    return k1, k2
  end

  # Simple (en/de)cryption operations; these only operate on numbers (not
  # bits, bytes or strings).  Encryption and decryption are not distinguised;
  # both operations can be performed using either key - it is up to the user
  # to decide which is required.  Length checking is also not imposed - it
  # is up to the user to only pass in numbers that are keylength bits or less.
  # Note: failing to do so will result in silent failures!
  def crypt(num)
    return Key.powmod(num, @keyv, @mod)
  end

  # Encrypt a message
  def encrypt(msg)
    mlen = msg.length
    nbo = String.new
    raise "Message too long" if mlen > 0xFFFFFFFF
    raise "Key too short" if bits < 24

    # Encode the message length and prepend it to the data.  Four bytes,
    # meaning a four-gigabyte limit.  Encode it in network byte order.
    4.times { nbo = (mlen & 0xFF).chr + nbo; mlen = mlen >> 8 }
    msg = nbo + msg

    # Compute the READ segment size.  This is two bytes less than the ESS
    # because we add two random padding bytes in each segment.  Then encrypt.
    bytes = (bits / 8) - 2
    crypt = method(:_encryptSegment)
    return _cryptMessage(msg, bytes, crypt)
  end

  # Decrypt a message
  def decrypt(msg)
    # Compute the READ segment size (the amount of data read from the message
    # for each segment).  This is one more than the ESS because of the extra
    # byte resulting from non-aligned modular division.
    bytes = (bits / 8) + 1

    # Decrypt the entire message
    crypt = method(:_decryptSegment)
    msg = _cryptMessage(msg, bytes, crypt)

    # Now only copy the bytes as prescribed by the 4-byte encoded length
    slen = msg[0...4]
    mlen = 0
    slen.each_byte { |b| mlen = (mlen << 8) + b }
    #raise "Message expands to be too large!" unless mlen < msg.length
    return msg[4...(mlen+4)]
  end

  # Take a string version of the key and decode it
  def key= (newKey)
    return nil if newKey == nil
    raise "Given key is not a string" if newKey.class != String
    kparts = newKey.split(":")
    raise "Malformed key" if kparts.length != 2 or kparts[0].length != kparts[1].length or kparts[0].length % 2 != 1
    @keyv = kparts[0].to_i(16)
    @mod = kparts[1].to_i(16)
    @bits = (kparts[0].length - 1) * 4
  end

  # Return the string copy of the key
  def key
    self.to_s
  end

  # Generate the string copy of the key
  def to_s
    return nil if @keyv == nil or @keyv == 0
    digits = (@bits / 4) + 1
    keyStr = @keyv.to_s(16)
    keyStr = "0" + keyStr while keyStr.length < digits
    modStr = @mod.to_s(16)
    modStr = "0" + modStr while modStr.length < digits
    return keyStr + ":" + modStr
  end


  ###   Protected Methods   ###
  protected

  # Generate a random number with the given number of bits that has the most
  # significant bit set, the second most significant bit set, or both.
  def Key.randomBits(bits)
    msbits = rand(3)+1           # most significant two bits
    lsbits = rand(2**(bits-2))   # all the rest

    # Combine the most significant and least significant bits
    msbits <<= (bits-2)
    return msbits | lsbits
  end

  # Generate a random prime number with exactly 'bits' length (technically,
  # bits-1 is also allowed)
  def Key.randomPrime(bits)
    check = Key.randomBits(bits)
    max = 2**bits
    check = check | 1      # make sure it's odd

    # Sieve first (filter out all numbers divisible by 3 and 5 to save time.
    # this reduces the number of primality checks by ~50%)
    s3, s5 = Key.sieveStart(check)
    while s3 == 0 or s5 == 0:
      s3 = 3 if s3 == 0
      s5 = 5 if s5 == 0
      check = check + 2
      s3, s5 = s3-1, s5-1
    end

    # Now skip up, checking for primality as we go
    while fast_prime(check, 12) == false:
      check = check + 2

      # Now sieve again
      s3, s5 = s3-1, s5-1
      while s3 == 0 or s5 == 0:
        s3 = 3 if s3 == 0
        s5 = 5 if s5 == 0
        check = check + 2
        s3, s5 = s3-1, s5-1
      end

      # Check our overflow condition
      if check > max
        check = (check >> 1) | 1
        s3, s5 = Key.sieveStart(check)

        # Now sieve AGAIN
        while s3 == 0 or s5 == 0:
          s3 = 3 if s3 == 0
          s5 = 5 if s5 == 0
          check = check + 2
          s3, s5 = s3-1, s5-1
        end
      end
    end # of if fast_prime 

    return check
  end

  # Calculate the number of remaining odd numbers before the given number
  # becomes divisible by certain primes
  def Key.sieveStart(num)
    # 3 is asy, 5 takes some translation
    s3 = num % 3
    s5 = num % 5
    if s5 == 2
      s5 = 4
    elsif s5 == 4
      s5 = 3
    elsif s5 == 1
      s5 = 2
    elsif s5 == 3
      s5 = 1
    end
    return s3, s5
  end

  # Generate a random number relatively prime to phi.  This ensures there
  # will be exactly one modular inverse of E.
  def Key.getEFromPhi(phi)
    ret, gcdVal = 0, 0
    while gcdVal != 1
      ret = rand(phi-130)+127 | 1
      gcdVal = gcd(ret, phi)
    end
    return ret
  end


  ###  Crypt Functions  ###

  # Perform the encoding, crypto, decoding.  bytes is output string size
  def _cipherSegment(data, bytes)
    # Encode
    num = 0
    data.each_byte { |b| num = (num << 8) | b }

    # Encrypt / decrypt
    num = self.crypt(num)

    # Decode
    res = String.new
    bytes.times do
      res = (num & 0xFF).chr + res
      num = num >> 8
    end
    return res
  end

  # Perform the encryption operation on a single segment with padding
  def _encryptSegment(plain)
    plain = plain + rand(256).chr + rand(256).chr

    # The len(plain)+1 in this case refers to the addition of an extra byte due
    # to the nature of the encryption operation; it does not have anything to
    # do with the padding or length-encoding
    return _cipherSegment(plain, plain.length+1)
  end

  # Perform the corresponding decryption operation
  def _decryptSegment(opaque)
    plain = _cipherSegment(opaque, opaque.length-1)
    return plain[0...-2]   # strip off padding
  end

  # Encrypt a message
  def _cryptMessage(msg, bytes, crypt)
    ret = String.new

    # Loop until the end, reading one segment at a time.  The bytes variable
    # represents the number of bytes read from the message (opaque or plaintext)
    # for each segment.  The number of bytes written to the output string is
    # determined by the crypt function.
    while msg and msg.length > 0
      # Grab one segment
      segment = msg[0...bytes]   # exclusive range
      msg = msg[bytes..-1]       # inclusive range

      # Pad the segment if it isn't the full size
      segment = segment + rand(256).chr while segment.length < bytes

      # Encrypt or decrypt as needed
      ret = ret + crypt.call(segment)
    end
    return ret
  end

  # Calculates the greatest common denominator of a and b using Euclidean Algo
  def Key.gcd(a, b)
    large, small, remain = 0, 0, 1

    # Order the given numbers (both assumed to be positive)
    if a > b
      large, small = a, b
    else
      large, small = b, a
    end

    # Iterate, Euclid-style!
    while remain > 0
      remain, large = large % small, small
      small = remain
    end

    return large # the previous "small" value
  end

  # Calculate the inverse of p mod m.  0 if none.  Uses reverse-Euclidean algo
  def Key.invmod(p, m)
    min1, min2 = 1, 0
    cur, remain, quotient = 0, 0, m

    # Loop until the remainder is either 0 or 1
    while p > 1 
      remain = quotient % p
      quotient = quotient / p
      cur = min2 - (min1*quotient)
      cur = cur % m
      min2 = min1
      min1 = cur
      quotient = p
      p = remain
    end

    # Now q holds the EA state.  Is there an inverse?  ie, gcd(p, m)==1
    return min1 if p==1
    return m2
  end

  # Calculate b^p mod m really, really fast
  def Key.powmod(b, p, m)
    res = 1

    # Loop through all the bits in the arbitrarily large exponent
    while p != 0:
      if p & 1 == 1
        res = (res * b) % m
      end
      b = (b * b) % m
      p = p >> 1
    end

    return res
  end

  # Test primality *fast*
  def Key.fast_prime(num, certainty = 20)
    exp = num - 1
    certainty.times do
      base = rand(num-5)+3
      return false if powmod(base, exp, num) != 1
    end
    return true
  end

end
#### End of aggregated 'rsa.rb' ####


# Chat 3.0 Message Format:
# ------------------------
# All messages have a 13 byte header, and this header is not encrypted:
#   - 1 byte for Type
#   - 4 bytes for length, NBO, size of entire message minus 21 (msg - hdr - 8)
#   - 8 bytes identifying the sender (first 8 bytes of MD5 of their pub key
#                                     or all zeros for the server)
#
#  (B)roadcast Messages:  Forwarded wholesale without inspection
#   - 8 bytes for the AES-ID (doubles as the IV, used for decryption)
#   - 8 bytes for the Channel-ID (all 0's for main channel broadcast)
#   - Message, which is length-8 bytes
#
#  (C)ommand Messages:  Forwarded to one user or all users
#   - 8 bytes for the AES-ID (doubles as the IV, used for decryption)
#   - 8 bytes for the recipient pub key hash (all 0's for broadcast)
#   - Message, which is length-8 bytes
#
#  (S)erver Messages:  Same form as Broadcast, only not forwarded.
#   - 8 bytes for AES-ID (always use server AES ID, NOT all zeros)
#   - Message, encrypted with server AES key, length bytes
#
#  (P)rivate Messages:  Forwarded only to one recipient
#   - 8 bytes for recipient's pub key hash
#   - Message, encrypted with recipient's public key, length bytes
#
#  (A)uth Messages:  Same as Private, only message is doubly-encrypted
#   - 8 bytes for recipient's pub key hash
#   - Message, encrypted with recipient's public key, then sender's private key
MSG_BROADCAST = 0x42
MSG_SERVER    = 0x53
MSG_PRIVATE   = 0x50
MSG_AUTH      = 0x41
MSG_COMMAND   = 0x43
MSG_MAXIMUM   = 0x1FFFF
EMPTY_ROOM    = "\x00" * 8

# Basic communication/encryption management object
class CryptoComm

  def initialize
    @keyring = Keyring.new
    @rsa_keys = { }
    @socket = nil
    @thread = nil
    @mutex = Monitor.new    # universal, top-level mutex object
  end

  # Build our reverse address book out of MD5 hashes
  def initialize_address_book(pub_key, prv_key, name)
    @our_keyhash = MD5::digest(pub_key)[0,8]
    @names = { @our_keyhash => name, EMPTY_ROOM => 'server' }
    @rsa_keys[name] = pub_key
    @pub_rsa = pub_key
    @prv_rsa = prv_key
  end

  attr_reader :socket, :keyring, :mutex, :rsa_keys, :names, :our_keyhash
  attr_writer :socket, :mutex

  # Are we connected or not?
  def connected?
    return !!@thread
  end

  # Get a sender's name by his key hash
  def sender_name(kh)
    @names[kh]
  end

  # Get a sender's keyhash by his name
  def sender_keyhash(name)
    return nil unless @rsa_keys[name]
    MD5::digest(@rsa_keys[name])[0,8]
  end

  # Send a message out to everyone (uses default key)
  def broadcast_message(msg, room = nil)
    room ||= EMPTY_ROOM
    opaque = @keyring.encrypt(msg)
    len = opaque.length + 8
    len = (len >> 24).chr + ((len >> 16) & 0xFF).chr +
          ((len >> 8) & 0xFF).chr + (len & 0xFF).chr
    msg = 'B' << len << @our_keyhash << @keyring.default.iv << room << opaque
    @socket.print(msg)
  end

  # Send a command out to a specific user, or to everyone
  def send_command(msg, rcpt = nil)
    rcpt = sender_keyhash(rcpt) if sender_keyhash(rcpt)
    rcpt ||= EMPTY_ROOM
    opaque, iv = nil, nil
    if rcpt == EMPTY_ROOM
      opaque = @keyring.open_encrypt(msg)
      iv = @keyring.open_key.iv
    else
      opaque = @keyring.encrypt(msg)
      iv = @keyring.default.iv
    end
    len = opaque.length + 8
    len = (len >> 24).chr + ((len >> 16) & 0xFF).chr +
          ((len >> 8) & 0xFF).chr + (len & 0xFF).chr
    msg = 'C' << len << @our_keyhash << iv << rcpt << opaque
    @socket.print(msg)
  end

  # Send a message to the server (users server AES id)
  def server_message(msg)
    opaque = @keyring.open_encrypt(msg)
    len = opaque.length
    len = (len >> 24).chr + ((len >> 16) & 0xFF).chr +
          ((len >> 8) & 0xFF).chr + (len & 0xFF).chr
    msg = 'S' << len << @our_keyhash << @keyring.open_key.iv << opaque
    @socket.print(msg)
  end

  # Send a private message - a remote command encrypted with the recipient's
  # public RSA key rather than our own private AES key.
  def send_private_command(msg, peer)
    type_byte = 'A'
    type_byte = 'P' if msg[0,4] == 'msg '
    rsa = @rsa_keys[peer]
    key_hash = sender_keyhash(peer)
    raise "invalid user #{peer}" unless rsa and key_hash
    rsa = Key.new(rsa)
    opaque = rsa.encrypt(msg)
    len = opaque.length
    len = (len >> 24).chr + ((len >> 16) & 0xFF).chr +
          ((len >> 8) & 0xFF).chr + (len & 0xFF).chr
    msg = type_byte << len << @our_keyhash << key_hash << opaque
    @socket.print(msg)
  end

  # Connect to this addr on this port using SSL
  def open_ssl_socket(addr, portNum)
    # Open up a socket and start SSL
    socket = TCPSocket.new(addr, portNum.to_i)
    ssl_context = OpenSSL::SSL::SSLContext.new
    ssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE
    ssl_socket = OpenSSL::SSL::SSLSocket.new(socket, ssl_context)
    ssl_socket.sync_close = true
    ssl_socket.connect
    @socket = ssl_socket
  end

  # Connect to this addr without using SSL
  def open_socket(addr, portNum)
    @socket = TCPSocket.new(addr, portNum.to_i)
  end

  # Shut everything down, right now!
  def shutdown
    @socket.close if @socket rescue nil
    @socket = nil
    @thread.kill if @thread rescue nil
    @thread = nil
  end

  # Start up a receiver thread, provide a block that expects to be called
  # callback(type, sender, room, message).  Obviously 'room' only makes
  # sense in the context of Broadcast messages
  # Calls callback(nil, nil, nil, "error message") on termination/exception
  def start_thread(&callback)
    return false if @thread
    @thread = Thread.new do
      begin
      loop do
        type = @socket.read(1)
        len = @socket.read(4)
        len = (len[0] << 24) + (len[1] << 16) + (len[2] << 8) + len[3]
        sender_hash = @socket.read(8)
        rki = @socket.read(8)   # either AES ID or recipient's public key hash
        opaque = @socket.read(len)
        msg = nil
        
        # Decrypt an AES message
        if type == 'B'
#$stderr.puts "Got broadcast message"
          room = opaque[0,8]
          opaque = opaque[8..-1]
          @mutex.synchronize do
            begin
              msg = @keyring.decrypt(rki, opaque)
              callback.call(type, sender_hash, room, msg)
            rescue
              callback.call(nil, nil, nil, "could not decrypt broadcast " +
                            "message from #{sender_name(sender_hash)}")
            end
          end
        elsif type == 'C'
#$stderr.puts "Got remote control message"
          rcpt = opaque[0,8]
          rcpt = nil if rcpt == EMPTY_ROOM
          opaque = opaque[8..-1]
          @mutex.synchronize do
            begin
              msg = @keyring.decrypt(rki, opaque)
              callback.call('C', sender_hash, !!rcpt, msg)
            rescue
              callback.call(nil, nil, nil, "could not decrypt control " +
                            "message from #{sender_name(sender_hash)}")
            end
          end
        elsif type == 'S'
#$stderr.puts "Got server message"
          @mutex.synchronize do
            begin
              msg = @keyring.decrypt(rki, opaque)
              callback.call('C', sender_hash, nil, msg)
            rescue
#$stderr.puts "ERROR: #{$!}\n#{$@.join("\n")}"
              callback.call(nil, nil, nil, "could not decrypt server " +
                            "message from #{sender_name(sender_hash)}")
            end
          end
        elsif type == 'P' or type == 'A'
#$stderr.puts "Got private message"
          @mutex.synchronize do
            rsa = Key.new(@prv_rsa)
            begin
              msg = rsa.decrypt(opaque)
              callback.call('C', sender_hash, nil, msg)
            rescue
              callback.call(nil, nil, nil, "could not decrypt private " +
                            "message from #{sender_name(sender_hash)}")
            end
          end
        elsif type == 'A'
          ####
        end
        
      end
      rescue
      end

      @mutex.synchronize { callback.call(nil, nil, nil, "recv thread terminated (reason)") }
    end  # of thread
    true
  end

end  # of class CryptoComm
#### End of aggregated 'comm3.rb' ####

class ChatConnection

  # Takes a callback block which accepts (type, sender, room, msg)
  def initialize(&callback)
    @comm = CryptoComm.new     # Our connection to the server
    @mutex = @comm.mutex
    @msg_callback = callback
    @room_names = { "\x00" * 8 => 'chat' }
    @room_ids = { 'chat' => "\x00" * 8 }
    @connected = false
  end

  attr_reader :room_names, :room_ids, :comm

  def connected?
    @connected
  end

  # Provide our mutex object to our owner
  def mutex
    @mutex
  end
  def mutex=(mtx)
    @mutex = mtx
    @comm.mutex = mtx
  end

  # method: connect to this addr on this port
  def connect(addr, port, pub_key, name)
    disconnect if @comm.connected?
    @comm.open_ssl_socket(addr, port.to_i)
    @comm.start_thread { |t, s, r, m| read_message(t, s, r, m) }
    @comm.server_message([ "name", pub_key, name ].join(' '))
    @connected = true
  end

  # Shut down the connection
  def disconnect
    @comm.shutdown
    @connected = false
    ################## send notice of disconnection?
  end

  # We've received a message from the network
  def read_message(type, sender_id, room_id, msg)
    sender_name = @comm.sender_name(sender_id) || 'unknown_user'
    room_name = @room_names[room_id]
    type = type[0] if type.class == String
    @msg_callback.call(type, sender_name, room_name, msg)
  end

  # We've received a chat message from the local user
  def chat_msg(msg, room = 'chat')
    room = @room_ids[room]
    @mutex.synchronize do
      @comm.broadcast_message(msg, room)
    end
  end

  # We're sending a command - either to everyone, or to a specific user
  def send_command(cmd_line, recipient = nil)
    @mutex.synchronize do
      @comm.send_command(cmd_line, recipient)
    end
  end

end  # of ChatConnection class
#### End of aggregated 'client3.rb' ####
$LOAD_PATH.push FILE_DIRECTORY
#### Aggregator included 'chat_window.rb' ####
#!/usr/bin/env ruby

# Copyright notice:
#  (C) 2009-2010
# This software is provided 'as-is' without any express or implied warranty.
# In no event will the authors be held liable for damages arising from the
# use of this software.  All license is reserved.


# This class defines the structure of the main chat window.  When it closes,
# the program exits.  It contains one or more room_pane widgets inside of
# a switcher which may be controlled by visible tabs.

require 'rubygems' rescue nil
require 'fox16'
require 'fox16/colors'
#### Aggregator included 'room_pane.rb' ####
#!/usr/bin/env ruby

# Copyright notice:
#  (C) 2009-2010
# This software is provided 'as-is' without any express or implied warranty.
# In no event will the authors be held liable for damages arising from the
# use of this software.  All license is reserved.


# This VIEW class defines the structure of a single chat pane (FXPacker
# subclass).  The chat pane contains one history element, one type-box element,
# and a horizontal selector between them.

require 'rubygems' rescue nil
require 'fox16'
require 'fox16/colors'

include Fox

class RoomPane < FXPacker
  TYPE_HEIGHT   =         34    # Initial height (pixels) of the type-box
  #TEXT_COLOR    = 0xff999999
  #BACK_COLOR    = 0xff000000
  TEXT_COLOR    = 0xff000000
  BACK_COLOR    = 0xffffffff
  CURSOR_COLOR  = 0xff333333
  FONT          =  'courier'
  FONT_SIZE     =          8
  SCROLLBARS    =      false
  PAD_HISTORY   =      false
  SPLITTER_SIZE =          1

  def initialize(parent, skin = {})
    super(parent, :opts => LAYOUT_FILL)
    @type_history = []      # history of things typed in this window
    @type_history_pos = 0   # our position while scrolling through the history
    @type_current = nil     # buffer saving our current line while scrolling

    # We may want a 2-pixel border on the inside-top of this pane, otherwise
    # no borders.
    self.padLeft = self.padBottom = self.padRight = 0

    # Split the history display from the type-box widget
    @splitter = FXSplitter.new(self, :opts => SPLITTER_VERTICAL | LAYOUT_FILL)

    # Fully automatic resizing isn't available with splitter-contained widgets
    @splitter.connect(SEL_COMMAND) { @type_height = @type.height }

    # Splitter children
    @history = FXText.new(@splitter, :height => height - TYPE_HEIGHT - 4,
      :opts => TEXT_WORDWRAP | LAYOUT_FILL_X | TEXT_READONLY)
    @type = FXText.new(@splitter, :opts => TEXT_WORDWRAP)
    apply_skin(skin)

    # Register callbacks
    @type.connect(SEL_KEYPRESS, method(:on_keypress))
    @history.connect(SEL_FOCUSIN) { @type.setFocus() }
  end

  # Apply the appearance variables contained in our 'skin' hash, accepting
  # (and setting) default values in their absence.
  def apply_skin(skin)
    @skin = skin
    @skin[:type_height]       ||=  TYPE_HEIGHT
    @skin[:text_color]        ||=  TEXT_COLOR
    @skin[:back_color]        ||=  BACK_COLOR
    @skin[:cursor_color]      ||=  CURSOR_COLOR
    @skin[:font]              ||=  FONT
    @skin[:font_size]         ||=  FONT_SIZE
    @skin[:scrollbars]        ||=  SCROLLBARS
    @skin[:pad_history]       ||=  PAD_HISTORY
    @skin[:splitter_size]     ||=  SPLITTER_SIZE

    # Apply
    @splitter.barSize = @skin[:splitter_size]
    self.padTop = (@skin[:pad_history] ? 2 : 0)
    @type.textColor = @history.textColor = @skin[:text_color]
    @type.backColor = @history.backColor = @skin[:back_color]
    @history.cursorColor = @skin[:back_color]
    @type.cursorColor = @skin[:cursor_color]
    @type_height = @skin[:type_height]
    @history.height = @history.height + @type.height - @type_height
    font = FXFont.new(app, @skin[:font], @skin[:font_size])
    @type.font = @history.font = font
    if @skin[:scrollbars]
      @type.scrollStyle &= ~VSCROLLER_NEVER
      @history.scrollStyle &= ~VSCROLLER_NEVER
    else
      @type.scrollStyle |= VSCROLLER_NEVER
      @history.scrollStyle |= VSCROLLER_NEVER
    end
  end

  # Psuedo-automatic layout updating
  def layout
    super
    unless @type_height == @type.height
      nhh = @history.height + @type.height - @type_height
      if nhh > 0
        @history.height = nhh
        layout
      end
    end
  end

  # Set GUI focus on our type box
  def type_focus
    @type.setFocus()
  end

  # This object generates only one synthetic event - character strings
  # typed by the user.
  def on_line(&blk)
    @on_line_block = blk
  end

  # Event handler that gets called when a user presses a key inside the
  # type box
  def on_keypress(sender, selector, data)
    code = data.code
    if code == KEY_Return or code == KEY_KP_Enter
      @on_line_block.call(@type.text)
      @type_history << @type.text.dup
      @type_history_pos = @type_history.length
      @type_current = nil
      @type.text = ''
      return true
    elsif code == KEY_Page_Up or code == KEY_Page_Down or
          code == KEY_KP_Page_Up or code == KEY_KP_Page_Down
      @history.handle(sender, selector, data)
    elsif code == KEY_Up
      @type_current = @type.text if @type_history_pos == @type_history.length
      if @type_history_pos > 0
        @type_history_pos -= 1
        @type.text = @type_history[@type_history_pos].dup
        @type.setCursorPos(@type.text.length)
      end
      return true
    elsif code == KEY_Down
      @type_history_pos += 1 if @type_history_pos < @type_history.length
      if @type_history_pos < @type_history.length 
        @type.text = @type_history[@type_history_pos].dup
        @type.setCursorPos(@type.text.length)
      elsif @type_current
        @type.text = @type_current
        @type.setCursorPos(@type.text.length)
        @type_current = nil
      end
      return true
    end
    return false
  end

  # Some text is getting appended to our history for display
  def disp(text)
    scroll = true
    scroll = false if @history.getBottomLine < @history.text.length
    text << "\n"
    @history.appendText(text)
    @history.setBottomLine(@history.text.length) if scroll
  end

end  # of class RoomPane


#### End of aggregated 'room_pane.rb' ####
#### Aggregator included 'whiteboard_pane.rb' ####
#!/usr/bin/env ruby

# Copyright notice:
#  (C) 2009-2010
# This software is provided 'as-is' without any express or implied warranty.
# In no event will the authors be held liable for damages arising from the
# use of this software.  All license is reserved.

####  Whiteboard Protocol  ####
# Whiteboard messages are a space-delimited set of commands.  Commands are
# made up of a type-byte and then a comma-delimited set of values.  As an
# example, here's a message containing two line commands:
# "L10,20,15,25 L15,20,10,25"
# The 'L' character specifies that each command is a line, and the LINE
# command takes four integer values - x1,y1,x2,y2.

require 'rubygems' rescue nil
require 'fox16'
require 'fox16/colors'

include Fox

class WhiteboardPane < FXPacker
  BOARD_WIDTH      = 480     # Initial window width
  BOARD_HEIGHT     = 320     # Initial window height
  IMG_WIDTH        = 1920    # Maximum width of our canvas
  IMG_HEIGHT       = 1080    # Maximum height of our canvas
  BUTTON_WIDTH     = 70
  BACK_COLOR       = 0xffffffff
  FRONT_COLOR      = 0xfff0000f
  BUFFER_TIME      = 1.1     # Seconds for which we buffer

  def initialize(parent, skin = {})
    super(parent, :opts => LAYOUT_FILL)
    @mouse_down = false
    @cmds = []
    @cmd_time = nil
    @colors = { 'R' => 0xff0000ff,
                'B' => 0xfff0000f,
                'G' => 0xff00aa00,
                'D' => 0xff000000 }
    @color = 'D'

    # We may want a 2-pixel border on the inside-top of this pane, otherwise
    # no borders.
    self.padLeft = self.padBottom = self.padRight = self.padTop = 0

    # Draw the top-level board
    frames = FXPacker.new(self, :opts => LAYOUT_FILL)

    # Buttons go on the right
    button_list = FXPacker.new(frames, :opts => LAYOUT_FILL_Y |
      LAYOUT_SIDE_RIGHT | LAYOUT_FIX_WIDTH, :width => BUTTON_WIDTH)
    button_clear = FXButton.new(button_list, "Clear", :opts => FRAME_RAISED |
      FRAME_THICK | LAYOUT_FILL_X | LAYOUT_SIDE_TOP)
    button_clear.connect(SEL_COMMAND) { clear_board }

    # Now draw the color buttons
    @colors.each do |c,v|
      button = FXButton.new(button_list, " ", :opts => FRAME_RAISED |
        FRAME_THICK | LAYOUT_FILL_X | LAYOUT_SIDE_TOP)
      button.connect(SEL_COMMAND) { @color = c }
      button.backColor = v
    end

    # Exit button at the bottom all by itself
    button_bye = FXButton.new(button_list, "Close", :opts => FRAME_RAISED |
      FRAME_THICK | LAYOUT_FILL_X | LAYOUT_SIDE_BOTTOM)
    button_bye.connect(SEL_COMMAND) { @on_line_block.call('/leave') }

    # Drawing area goes on the left
    cframe = FXHorizontalFrame.new(frames, :opts => LAYOUT_FILL | FRAME_SUNKEN |
      FRAME_THICK | LAYOUT_SIDE_LEFT, :padLeft => 0, :padRight => 0,
      :padTop => 0, :padBottom => 0, :hSpacing => 0, :vSpacing => 0)
    @canvas = FXCanvas.new(cframe, :opts => LAYOUT_FILL)
    @canvas.connect(SEL_PAINT, method(:board_draw))
    @canvas.connect(SEL_LEFTBUTTONPRESS, method(:left_button_down))
    @canvas.connect(SEL_LEFTBUTTONRELEASE, method(:left_button_up))
    @canvas.connect(SEL_MOTION, method(:mouse_motion))

    # Backup of the canvas on which we're drawing
    @image = FXImage.new(app, :width => 1920, :height => 1080)
    @image.create
    FXDCWindow.new(@image) do |dc|
      dc.foreground = BACK_COLOR
      dc.fillRectangle(0, 0, 1920, 1080)
    end
  end

  # Redraw the whole board?  Restore an image?
  def board_draw(*params)
    FXDCWindow.new(@canvas) do |dc|
      dc.drawImage(@image, 0, 0)
    end
  end

  # Clear the whole board (local only)
  def clear_board
    FXDCWindow.new(@image) do |dc|
      dc.foreground = BACK_COLOR
      dc.fillRectangle(0, 0, IMG_WIDTH, IMG_HEIGHT)
    end
    board_draw
  end

  # This object generates only one synthetic event - character strings
  # "typed" by the user.
  def on_line(&blk)
    @on_line_block = blk
  end

  # The left mouse button has been pressed
  def left_button_down(sender, selector, event)
    @canvas.grab
    @mouse_down = true
  end

  # The left mouse button has been released
  def left_button_up(sender, selector, event)
    @canvas.ungrab
    @mouse_down = false
    flush_commands
    board_draw
  end

  # The mouse has moved.  Do something if the button is down
  def mouse_motion(sender, selector, event)
    return nil unless @mouse_down

    # Draw the temporary line just for immediate user feedback
    FXDCWindow.new(@canvas) do |dc|
      dc.foreground = @colors[@color]
      dc.drawLine(event.last_x, event.last_y, event.win_x, event.win_y)
    end

    # Draw the permanent line to our buffer
    FXDCWindow.new(@image) do |dc|
      dc.foreground = @colors[@color]
      dc.drawLine(event.last_x, event.last_y, event.win_x, event.win_y)
    end

    # Now send the line to the room
    buffer_command("L,#{@color},#{event.last_x},#{event.last_y}" +
                   ",#{event.win_x},#{event.win_y}")
    true
  end

  # Buffer commands so we can send them in chunks
  def buffer_command(cmd)
    @cmd_time ||= Time.now.to_f
    @cmds << cmd
    flush_commands if Time.now.to_f - @cmd_time > BUFFER_TIME
  end

  # Send all the buffered commands, if any
  def flush_commands
    @cmd_time = nil
    @on_line_block.call(@cmds.join(' ')) unless @cmds.empty?
    @cmds = []
  end

  # We've gotten a list of drawing commands from the room.  Let's draw them!
  def disp(text)
    FXDCWindow.new(@image) do |dc|
      text.split(' ').each do |cmd|
        cmd = cmd.split(',')
        if cmd.first == 'L'
          dc.foreground = @colors[cmd[1]].to_i
          dc.drawLine(cmd[2].to_i, cmd[3].to_i + 1, cmd[4].to_i, cmd[5].to_i + 1)
        end
      end
    end
    board_draw
  end

end  # of class WhiteboardPane


#### End of aggregated 'whiteboard_pane.rb' ####

include Fox

class ChatWindow < FXMainWindow
  include Responder
  
  WINDOW_HEIGHT = 320
  WINDOW_WIDTH  = 480
  WINDOW_TITLE  = "Chat 3.0"
  SHOW_TABS     = true
  ID_NEXT_TAB   = ID_LAST + 1
  ID_PREV_TAB   = ID_NEXT_TAB + 1

  def initialize(app, skin = {})
    @skin = skin
    @empties = []
    @waiting_tabs = {}

    # Set up some default appearance values first
    @skin[:window_height]    ||=  WINDOW_HEIGHT
    @skin[:window_width]     ||=  WINDOW_WIDTH
    @skin[:window_title]     ||=  WINDOW_TITLE
    @skin[:show_tabs]        ||=  SHOW_TABS

    # Create the main window
    super(app, @skin[:window_title], :width => @skin[:window_width],
                                     :height => @skin[:window_height])
    
    # Top level container for the tab bar and the switcher.  We don't let
    # the tab system actually manage anything, because we want to be able
    # to turn tabs on and off.  So we have a tab bar with no content that
    # drives a switcher (or just a switcher, if so chosen).
    packer = FXPacker.new(self, :opts => LAYOUT_FILL)
    packer.padTop = packer.padBottom = packer.padLeft = packer.padRight = 0
    packer.vSpacing = 0

    # Tab bar and its empty content
    @tabs = FXTabBook.new(packer, :opts => LAYOUT_FILL_X | LAYOUT_SIDE_TOP)
    @tabs.padBottom = @tabs.padTop = @tabs.padLeft = @tabs.padRight = 0
    @tab_names = [ FXTabItem.new(@tabs, "chat", nil) ]
    empty = FXPacker.new(@tabs)
    empty.padBottom = empty.padTop = empty.padLeft = empty.padRight = 0
    @empties << empty

    # The top level switcher.  Each switchable instance is a RoomPane instance
    @switcher = FXSwitcher.new(packer, :opts => LAYOUT_FILL)
    @switcher.padBottom = @switcher.padTop = 0
    @switcher.padLeft = @switcher.padRight = 0
    @channels = [ [ 'chat', RoomPane.new(@switcher, skin) ] ]
    @channels.first.last.type_focus rescue nil

    # Tabs are always off when there's only one room to display
    @tabs.hide

    # Tab selection should map directly to the switcher
    @tabs.connect(SEL_COMMAND, method(:on_tab_select))

    # Hook up keyboard accelerators old-school FXRuby style
    FXMAPFUNC(SEL_COMMAND, ID_NEXT_TAB, :next_tab)
    accelTable.addAccel(fxparseAccel("Ctrl+N"),
                        self, FXSEL(SEL_COMMAND, ID_NEXT_TAB))
    accelTable.addAccel(Fox.MKUINT(KEY_Tab, CONTROLMASK),
                        self, FXSEL(SEL_COMMAND, ID_NEXT_TAB))
    accelTable.addAccel(Fox.MKUINT(KEY_KP_Tab, CONTROLMASK),
                        self, FXSEL(SEL_COMMAND, ID_PREV_TAB))
    FXMAPFUNC(SEL_COMMAND, ID_PREV_TAB, :prev_tab)
    accelTable.addAccel(fxparseAccel("Ctrl+Shift+N"),
                        self, FXSEL(SEL_COMMAND, ID_PREV_TAB))
    accelTable.addAccel(Fox.MKUINT(KEY_Tab, CONTROLMASK | SHIFTMASK),
                        self, FXSEL(SEL_COMMAND, ID_PREV_TAB))
    accelTable.addAccel(Fox.MKUINT(KEY_KP_Tab, CONTROLMASK | SHIFTMASK),
                        self, FXSEL(SEL_COMMAND, ID_PREV_TAB))
    accelTable.addAccel(Fox.MKUINT(KEY_ISO_Left_Tab, CONTROLMASK | SHIFTMASK),
                        self, FXSEL(SEL_COMMAND, ID_PREV_TAB))
  end

  def create
    super
    show(PLACEMENT_SCREEN)
  end

  # Turn activity notification on or off for the given tab index
  def tab_notify(indx, notify)
    notify = false if indx == @tabs.current
    prior = @waiting_tabs[indx]
    @waiting_tabs[indx] = notify
    return nil unless prior ^ notify   # leave if status isn't changing
    if notify
      @tab_names[indx].text = @tab_names[indx].text + '+'
    else
      @tab_names[indx].text = @tab_names[indx].text[0...-1]
    end
  end

  def select_tab(indx)
    @tabs.current = indx
    tab_notify(indx, false)
    @switcher.current = indx
    @on_room_block.call(@channels[indx].first)
    @channels[indx].last.type_focus rescue nil
  end
  
  # A user has clicked on a tab
  def on_tab_select(sender, selector, e)
    select_tab(@tabs.current)
  end

  # Register a callback block for handling user-typed lines in one of the
  # RoomPane widgets.
  def on_line(&blk)
    @on_line_block = blk
    @channels.each { |name,pane| pane.on_line(&blk) }
  end

  # Register a callback for when the user selects a different room (or
  # private message context) using the GUI tabs.
  def on_room_change(&blk)
    @on_room_block = blk
  end

  # Add text to the provided room (or private message context)
  # A room name of :current means send to the current room, whatever it is.
  # A room name of :global means send it to all rooms.
  def room_append(room_name, text)
    room_name = @channels[@switcher.current].first if room_name == :current

    # Find the room (or rooms) to which we should send this message
    channel = @channels.select do |name,pane|
      room_name == name or room_name == :global
    end

    # Do we need to unhide a room?
    if channel.length == 1 and room_name.class == String
      indx = @channels.index(channel.first)
      unless indx == 0
        @tab_names[indx].show
        (@tabs.create ; @tabs.show) if @skin[:show_tabs]
      end
    end

    # Do we need to create a room?  I think we might!
    if channel.empty? and room_name.class == String
      new_tab(room_name)
      channel = [ @channels.last ]
    end
    channel.each do |chan|
      indx = @channels.index(chan)
      chan.last.disp(text)
      tab_notify(indx, true) unless room_name == :global
    end
  end

  # Adding a new tab and switcher element.  Optionally you can specify a
  # class (a pane type) which will be spawned.  RoomPane is spawned by default.
  # Checks for duplicates automatically.
  def new_tab(name, klass = RoomPane)
    # Don't do anything if we already have this tab
    @channels.each { |cname,_| return nil if cname == name }

    # Add the visual indication of this tab
    @tab_names << FXTabItem.new(@tabs, name, nil)
    empty = FXPacker.new(@tabs)
    empty.padBottom = empty.padTop = empty.padLeft = empty.padRight = 0
    @empties << empty

    # Create the content of this channel - probably a RoomPane
    new_channel = klass.new(@switcher, @skin)
    @channels << [ name, new_channel ]
    new_channel.create
    new_channel.on_line(&@on_line_block)   # register our callback function

    # Show the tabs (if so desired) now that we know we have more than one.
    (@tabs.create ; @tabs.show) if @skin[:show_tabs]
  end

  # Remove the named tab and hide its corresponding switcher element
  def remove_tab(name)
    indx = @channels.index(@channels.find { |room,_| room == name }).to_i
    return nil unless indx > 0

    # Update this particular tab name and our switcher context
    @tab_names[indx].hide
    @tabs.current = 0
    @switcher.current = 0
    
    # Now update the tab bar as a whole and redraw
    if visible_tabs < 2
      @tabs.hide
    end
    @tabs.recalc
    @on_room_block.call(@channels[0].first)
  end

  def next_tab(sender, sel, data)
    max = @tab_names.length
    indx = (@tabs.current + 1) % max
    until @tab_names[indx].visible?
      indx = (indx + 1) % max
    end
    select_tab(indx)
  end

  def prev_tab(sender, sel, data)
    max = @tab_names.length
    indx = (@tabs.current - 1) % max
    until @tab_names[indx].visible?
      indx = (indx - 1) % max
    end
    select_tab(indx)
  end
  
  # The sneaky user has changed the room without the GUI.  Bastards!
  def room_change(room_name)
    indx = @channels.index(@channels.find { |room,_| room == room_name })
    unless indx
      indx = @channels.length
      new_tab(room_name)
    end
    @tabs.current = indx
    @switcher.current = indx
    @tab_names[indx].show
    (@tabs.create ; @tabs.show) if @skin[:show_tabs] and indx != 0
    tab_notify(indx, false)
    @tabs.recalc
    @channels[indx].last.type_focus rescue nil
  end

  # Return the number of visible (unhidden) tabs
  def visible_tabs
    count = 0
    @tab_names.each { |x| count += 1 if x.visible? }
    count
  end

end  # of class ChatWindow

#### End of aggregated 'chat_window.rb' ####

# Ruby tool used to grab the source of included files, not just their content
SCRIPT_LINES__ = {}

RSA_BITS = 2416

# This is the dialog which pops up if you don't have a key
# (usually the first time you run chat)
class WelcomeBox < FXDialogBox
  attr_accessor :username
  def initialize(parent)
    @username = ""
    # Window decoration options
    super(parent, "Welcome to Chat 3.0", DECOR_TITLE | DECOR_BORDER |
      LAYOUT_FIX_WIDTH | LAYOUT_FIX_HEIGHT)
    
    # Main dialog frame
    frame = FXVerticalFrame.new(self, LAYOUT_FILL_X | LAYOUT_FILL_Y)
    
    # Informational text
    text = "Welcome to Chat 3.0!\n\n" +
     "You must first enter a username and generate an encryption key.\n\n" +
     "Your username may include letters, numbers, and the underscore\n" +
     "character, and should be at least 3 characters long."
    FXLabel.new(frame, text, nil, LAYOUT_CENTER_X)
    
    # Username text and box
    FXLabel.new(frame, "Unique Username:", nil, LAYOUT_CENTER_X)
    uname_field = FXTextField.new(frame, 20, nil, 0, TEXTFIELD_NORMAL |
      LAYOUT_CENTER_X | TEXTFIELD_LIMITED)
    
    # More informational text
    FXLabel.new(frame, "(you can change this any time you want)", nil,
      LAYOUT_CENTER_X)
    
    # Buttons subframe
    b_frame = FXPacker.new(frame, LAYOUT_FILL_X)
    
    # Exit Button and handler
    exit_button = FXButton.new(b_frame, "Cancel", :opts => BUTTON_NORMAL |
      LAYOUT_SIDE_LEFT | LAYOUT_FIX_WIDTH, :width => 75)
    exit_button.connect(SEL_COMMAND) do 
      self.handle(self, MKUINT(FXDialogBox::ID_CANCEL, SEL_COMMAND), nil)
    end

    # Generate Key Button and handler
    gen_button = FXButton.new(b_frame, "Generate", :opts => BUTTON_NORMAL |
      LAYOUT_SIDE_RIGHT | LAYOUT_FIX_WIDTH, :width => 75)
    gen_button.connect(SEL_COMMAND) do 
      # quick test to see if the username is valid...
      if not valid_username?(uname_field.text)
        text = "Username may comprise only alphanumeric and underscore\n" +
               "and must be longer than 2 characters."
        FXMessageBox.error(self, MBOX_OK, "Error", text)
      else # username is valid
        @username = uname_field.text # needs to be accessible to calling code 
        self.handle(self, MKUINT(FXDialogBox::ID_ACCEPT, SEL_COMMAND), nil)
      end
    end
  end 
  
  private
  # helper function to see if username meets character requirements
  def valid_username?(username)
    # allow only these characters
    valid = ("a".."z").to_a + ("A".."Z").to_a + ("0".."9").to_a + "_".to_a 
    return false if username.length < 3
    username.each_byte { |c| return false if not valid.include?(c.chr) }
    return true
  end
  
end

# This is the dialog which pops up while your key is being generated
class KeyGenBox < FXDialogBox
  def initialize(app)	
    super(app, "Generating Your Key")

    # Progress bar
    bar = FXProgressBar.new(self, nil, 0, LAYOUT_FILL_X)
    bar.total = 100

    # Text
    FXLabel.new(self, "This takes about a minute")

    # Cancel button & handler
    cancelButton = FXButton.new(self, "Cancel", nil, nil, 0, BUTTON_NORMAL |
      LAYOUT_CENTER_X)
    cancelButton.connect(SEL_COMMAND) do 
      Kernel.exit(0) # Allow users to quit
    end

    # Imitate Windows progressbar behavior
    app.addTimeout(250, :repeat => true) do
      bar.progress += rand(10) - bar.progress/10
    end
  end
end


# The top-level Chat 3.0 client class.  Methods in user3.rb and guser3.rb are
# defined in the scope of this class.
class Chat3

  def initialize
    @cmds = []
    @controls = []
    @var = {}
    @fox_app = FXApp.new
    @window = ChatWindow.new(@fox_app)
    @window.on_line { |txt| local_line(txt) }
    @window.on_room_change { |room| @var[:room] = room }
    @connection = ChatConnection.new do |type, sender, room, msg|
      if type == MSG_BROADCAST
        dispatch :incoming_broadcast, sender, room, msg
        remote_chat(sender, room, msg) unless msg.empty?
      elsif type == MSG_COMMAND
        remote_command(sender, msg)
      else
      end
    end
    load_command_methods()
  end

  def connect(addr, port)
    raise "You are not registered!" unless @var[:pub_rsa] and @var[:our_name]
    @connection.connect(addr, port.to_i, @var[:pub_rsa], @var[:our_name])
  end

  def run
    @fox_app.create
    dispatch(:startup)
    @fox_app.run
    @connection.disconnect
  end

  def disconnect
    @connection.disconnect
  end

  # We've received a control from the server or from another user
  def remote_command(sender, msg)
    indx = ((msg =~ /\W/) || msg.length)
    cmd = msg[0...indx]
    body = msg[indx+1..-1].to_s
    @connection.mutex.synchronize do
      if @controls.include? cmd
        ############## dispatch incoming remote control event
        begin
          self.send("remote_#{cmd}", sender, body)
        rescue
          if @var[:verbose_error]
            add_error("remote command from #{sender} (#{cmd}) failed: #{$!}" +
                      "\n#{$@.join("\n")}")
          else
            add_error("remote command from #{sender} (#{cmd}) failed: #{$!}")
          end
        end
      else
        add_error "received invalid control from #{sender}: '#{cmd}'"
      end
    end
  end

  # We've received a chat message
  def remote_chat(sender, room, msg)
    add_msg("#{sender}: #{msg}", room)
    #@window.room_append(room, "#{sender}: #{msg}")
    #add_msg "<#{room || 'unknown'}> #{sender}: #{msg}"
  end

  # We need to dispatch an event
  def dispatch(event_type, *params)
    @connection.mutex.synchronize do
      begin
        self.send("event_#{event_type}", *params)
      rescue
        add_error("Event #{event_type} raised an exception: #{$!}")
      end
    end
  end

  # Handle one line of local input
  def local_line(msg)
    if msg[0,1] == '/'
      msg[0,1] = ''
      indx = ((msg =~ /\W/) || msg.length)
      cmd = msg[0...indx]
      body = msg[indx+1..-1].to_s
      @connection.mutex.synchronize do
        if @cmds.include? cmd
          ############## dispatch incoming local control event
          begin
            self.send("local_#{cmd}", body)
          rescue
            if @var[:verbose_error]
              add_error("local command '#{cmd}' generated an exception: #{$!}\n#{$@.join("\n")}")
            else
              add_error("#{$!}")
            end
          end
        else
          add_error "invalid local command: '#{cmd}'"
        end
      end
    elsif msg.length > 0
      if @connection.connected?
        dispatch :outgoing_broadcast, msg
        @connection.chat_msg(msg, @var[:room])
      else
        add_error "not connected to server"
      end
    end
  end

  # This method gets invoked if the local user's environment file (env.yml)
  # does not contain their username and public/private RSA key pair.
  def keygen_tool
    # Spawn a welcome & get username box
    welcome_box = WelcomeBox.new(@fox_app)
    welcome_box.create
    
    # Execute box, bail if 'Exit' is clicked
    Kernel.exit(0) if welcome_box.execute(PLACEMENT_OWNER) == 0

    # Otherwise, "Generate Key" must have been clicked, so do that.
    wait_box = KeyGenBox.new(@fox_app)
    wait_box.create
    wait_thread = Thread.new { wait_box.execute(PLACEMENT_OWNER) }
    
    # Acutally generate the RSA keypair here
    keys = Key.new
    pub_rsa, prv_rsa = Key.keygen(RSA_BITS)
    
    # Key is done; close waitBox
    wait_box.close
    return welcome_box.username, pub_rsa.to_s, prv_rsa.to_s
  end

  # Load methods which can be used for /cmd commands
  def load_command_methods()
    begin
      # Add all the newly-defined methods to our call list
      @mlist ||= []
      begin
        load 'user3.rb'          # install the user-defined methods
        load 'guser3.rb'         # install the GUI extensions
        load 'local.rb'          # methods local to the user
      rescue LoadError; end

      # Load in the included files' code, but only once
      unless @var[:script_lines]
        @var[:script_lines] = []
        SCRIPT_LINES__.each do |k,v|
          @var[:script_lines] += v if k.include? 'user3.rb'
        end
      end
      new_methods = self.methods.select { |m| not @mlist.include? m }
      @mlist = self.methods

      # Find, translate and add any new user commands
      @cmds += new_methods.select { |m| m =~ /^local_/ }
      @cmds.collect! { |cmd| cmd.sub 'local_', '' }

      # Find and add any new control handlers
      @controls += new_methods.select { |m| m =~ /^remote_/ }
      @controls.collect! { |cmd| cmd.sub 'remote_', '' }
    rescue SyntaxError
      add_error "Plugins could not be loaded (#{$!})."
    rescue
      add_error $!
    end
  end  # of load_command_methods()

  # Print a message to the provided room.  :global results in the message
  # being printed to all rooms, :current means the current visible room,
  # :notice means the notice buffer.
  def add_msg(msg, room)
    if room == :notice
      room = :current
    end
    dispatch(:display_line, msg, room)
    @window.room_append(room, msg)
  end

  # Print an error to the screen
  def add_error(msg)
    add_msg "* Error: #{msg}", :notice
  end

end  # of class Chat3

# For the sake of the aggregator, require these here
#### Aggregator included 'user3.rb' ####
# Copyright notice:
#  (C) 2009-2010
# This software is provided 'as-is' without any express or implied warranty.
# In no event will the authors be held liable for damages arising from the
# use of this software.  All license is reserved.


# Okay.  Now this is where shit gets really interesting.  Add any method
# definitions you wish inside this file.  They will get defined at
# RUN TIME.  Any method you insert here will be able to respond to
# "/cmd arg1 arg2" commands from the prompt.  All methods here should accept
# a single array param, ie:  def my_method(*args).  Raise exceptions to exit
# gracefully.
#
# Prepend "local_" to local /command definitions
# Prepend "remote_" to remote control handlers
# Event handlers are all already defined.
# Prepend "_" to helper methods
# Events will be prepended with "event_"
#
# Useful internal methods:
#   add_msg(msg)              - print a message to the local user
#   add_error(msg)            - print an error message to the local user
#   load_command_methods      - loads methods defined here
#   @connection.chat_msg      - send a chat message to all users
#   @connection.send_command  - send a command to all users or to one user:
#                               send_command(cmd_string) - all users
#                               send_command(cmd_string, name) - one user   
#   dispatch(:event, *args)   - send an event
#
# Useful internal variables:
#   @cmds                  - list of names of the methods defined here
#   @var                   - a hash where you can story any variable you like
#                            (please use :symbols)

# All definitions will be associated with this object:
class Chat3

# Put your definitions below this line:
# --------------------------------------------------------------------------


# This is the version number of the code.  The env3.yml also holds the version
# number of the last code it ran.  This is how software upgrades are detected.
# Version numbers can be compared with the _versioncmp() function.
def _version
  '3.0.1'
end


# Returns -1 if a < b, 0 if a == b, and 1 if a > b
def _versioncmp(a, b)
  a, b = a.to_s.split('.'), b.to_s.split('.')
  [a.length, b.length].max.times do |i|
    return -1 if a[i].to_i < b[i].to_i
    return 1 if a[i].to_i > b[i].to_i
  end
  return 0
end


# Print a notice to the screen.  Types are :notice, :global, :crypto, :error.
# If type is String instance, it is a room name and the notice belongs to
# that room.
def _notice(msg, type = :notice)
  if type == :error
    add_error(msg)
  else
    add_msg("* #{msg}", type)
  end
end


# Convert a key-hash into a fingerprint using the standard Chat 3.0 format
def _fingerprint(key_hash)
  fp = []
  key_hash.each_byte { |x| fp << ("%02x" % x) }
  ret = []
  4.times { ret << fp.shift + fp.shift }
  ret.join(' ')
end


# We're resetting all of our network state for a reconnection
def _network_init
  # Flush out all blacklisted state
  @var[:blacklist_env].each { |rm| @var.delete rm unless rm == :blacklist_env }

  # Add the key hashes
  @var[:user_keys].each do |name, key|
    keyhash = MD5::digest(key)[0,8]
    @connection.comm.rsa_keys[name] = key
    @connection.comm.names[keyhash] = name
  end

  # Keys and access
  @var[:granted] = [ @var[:our_name] ]
  @var[:granted_by] = [ @var[:our_name] ]
  @var[:revoked] ||= []

  # Chat rooms and presense
  @var[:room] = 'chat'        # current room
  @var[:membership] = {}      # maps room-name to known room members' keyhashes
  @var[:presence] = {}        # maps peer keyhash to presence + salutation
  @var[:membership][EMPTY_ROOM] = [ @connection.comm.our_keyhash ]
  @var[:presence][@connection.comm.our_keyhash] = [ 'offline', '' ]
end


# A user's presense is being adjusted.  Valid operations are:
#  [ 'join', 'leave', 'away', 'back', 'online', 'offline' ]
# Params:
#  - op:       operation from the list given above
#  - peer:     public key hash of peer
#  - room:     local string name of room (only for join and leave)
#  - msg:      user's custom salutation (may be blank)
#  - notify:   print a _notice() notification?
# Returns: [ peer_name, op, status, room ]
def _adjust_presence(op, peer_keyhash, room, msg, notify = true)
  peer_name = _user_name(peer_keyhash)
  room = nil unless op == 'leave' or op == 'join'

  # Find the prior and current presence state
  prior = (@var[:presence][peer_keyhash] || []).first
  current = prior
  current = 'online' if op == 'online' or op == 'back'
  current = 'away' if op == 'away'

  # Find the new salutation for this user
  status = (@var[:presence][peer_keyhash] || []).last.to_s
  status = msg if [ 'away', 'back', 'online' ].include?(op) or msg.length > 0
  msg = ''
  msg = ": #{status}" if status.length > 0

  # Special case - logging off means leaving every chat room implicitly
  if op == 'offline'
    @var[:membership].each { |_,r| r.delete peer_keyhash }
  end

  # Update the presence state
  @var[:presence][peer_keyhash] = [ current, status ]

  # Notify the user if so instructed
  if (notify)
    if room
      _notice "#{peer_name} has #{op == 'join' ? 'joined' : 'left'}" +
              " room #{room}.", room
    elsif op == 'offline'
      _notice "#{peer_name} has disconnected#{msg}", :notice
      @var[:presence].delete peer_keyhash
    elsif op == 'away' and prior != current
      _notice "#{peer_name} is away#{msg}", :notice
    elsif op == 'back' or current == 'online' and prior != current
      _notice "#{peer_name} is back#{msg}", :notice
    end
  end
  return [ peer_name, op, status, room ]
end


# Fine a user's name by their keyhash and vice-versa
def _user_name(kh)
  @connection.comm.sender_name(kh) || 'unknown_user'
end
def _user_keyhash(name)
  @connection.comm.sender_keyhash(name)
end


# Open a file; report only initial failures (don't want to bug the user).
# Create the containing directory if it does not exist
def _open_sefile(filename, *args)
  require 'ftools'
  ret = nil
  fname = FILE_DIRECTORY
  begin
    File.makedirs FILE_DIRECTORY unless File.exist? FILE_DIRECTORY
    fname = File.join(FILE_DIRECTORY, filename)
    ret = File.open(fname, *args) { |f| yield f }
    @var.delete :file_open_raised
  rescue Errno::ENOENT
  rescue
    already_raised = @var[:file_open_raised]
    @var[:file_open_raised] = true
    raise "could not open file \"#{fname}\"" unless already_raised
  end
  ret
end


# Save our environment variables, except those that are blacklisted
def _save_env
  require 'yaml'
  w_var = @var.dup
  @var[:blacklist_env].each { |b| w_var.delete b } if @var[:blacklist_env]
  _open_sefile('env3.yml', 'w') { |f| YAML.dump(w_var, f) }
end


# Load our environment variables
def _load_env
  require 'yaml'
  r_var = _open_sefile('env3.yml') { |f| YAML.load(f) }
  @var.delete :file_open_raised
  r_var.each { |k,v| @var[k] = v } if r_var
end


# Send a remote control to a provided user, optionally with RSA.  Set peer
# to nil to deliver a remote control to the whole room.
def _remote_control(peer, command, body, use_rsa = false)
  raise "Invalid user, #{peer}" if (peer or use_rsa) and not _user_keyhash(peer)
  if use_rsa
    @connection.comm.send_private_command("#{command} #{body}", peer)
  else
    peer = _user_keyhash(peer) if peer
    @connection.comm.send_command("#{command} #{body}", peer)
  end
end


# Send a remote control to the server
def _server_control(command, body = nil)
  @connection.comm.server_message("#{command} #{body}")
end


# Pull tokens off the beginning of a block of text, leaving the remaining
# block otherwise the same.
def _pop_token(body)
  indx = body.index(' ') || body.length
  token = body[0...indx]
  body[0..indx] = ''
  return token
end


# Send a remote control to the provided user.  Arguments are:  recipient name,
# command, contents.
def local_remote_control(body)
  peer = _pop_token(body)
  command = _pop_token(body)
  _remote_control(peer, command, body)
end


# Connect to a chat 3.0 server - two arguments: host, IP.
def local_connect(body)
  host = _pop_token(body)
  port = _pop_token(body).to_i
  if host.length < 1
    begin
      host, port = @var[:last_connection]
    rescue
      raise "usage: /connect <hostname> [port]"
    end
  end
  port = 9000 if port == 0
  begin
    connect(host, port)
    @var[:last_connection] = [ host, port ]
    _save_env
  rescue
    _notice "Could not connect to #{host}:#{port} - #{$!}", :error
  end
end


# Reload the control code in user3.rb
def local_reload(body)
  load_command_methods()
  _notice "command methods reloaded", :notice
end


# Rename yourself (one argument - your new name) or someone else (two
# arguments - old name, new name).
def local_nick(body)
  name1 = _pop_token(body)
  name2 = _pop_token(body)
  raise "Usage: /nick <old_name> <new_name>" if name1.to_s.empty?
  if name2.to_s.empty?
    name2 = name1
    name1 = @var[:our_name]
  end
  raise "Name '#{name2}' is already in use" if @var[:user_keys][name2]

  # Perform the renaming
  kh = @connection.comm.sender_keyhash(name1)
  key = @connection.comm.rsa_keys[name1]
  raise "Invalid user name: '#{name1}'" unless kh and key
  @connection.comm.rsa_keys[name2] = key
  @connection.comm.rsa_keys.delete(name1)
  @connection.comm.names[kh] = name2
  @var[:user_keys][name2] = key
  @var[:user_keys].delete name1
  @var[:granted].collect! { |x| x = name2 if x == name1 ; x }
  @var[:granted_by].collect! { |x| x = name2 if x == name1 ; x }
  @var[:revoked].collect! { |x| x = name2 if x == name1 ; x }
  
  # And lastly, if this is us, update our special name attribute
  @var[:our_name] = name2 if @var[:our_name] == name1
  _notice("#{name1} is now known as #{name2}")
  _save_env
end


# Display a list of users you know and their key status.  No arguments.
def local_keys(body)
  disp = " -- Registered Accounts --\n"
  disp << "Name:        RSA Fingerprint:      Status:\n"
  @var[:user_keys].each do |name,key|
    key_hash = MD5::digest(key)[0,8]
    fingerprint = _fingerprint(key_hash)
    status = []
    status = [ "Granted" ] if @var[:granted].include?(name)
    status = [ "Revoked" ] if @var[:revoked].include?(name)
    if @var[:presence][key_hash]
      status << @var[:presence][key_hash].first
    else
      status << "offline"
    end
    disp << "#{(name+(' '*12))[0,12]} #{fingerprint}   #{status.join(', ')}\n"
  end
  _notice(disp)
end


# Change the timestamp format - accepts string in strftime() format.  Spaces
# are allowed.
def local_timestamp(body)
  @var[:timestamp] = body
  _save_env
  _notice "Timestamp format changed"
end


# Disconnect from the current server - no arguments.
def local_disconnect(body)
  @connection.disconnect
  _network_init
  _notice "disconnected", :global
end


# Grant your session key to the provided user - 1 argument.
def local_grant(peer)
  key = @connection.comm.rsa_keys[peer]
  raise "invalid user: #{peer}" unless key
  if @var[:revoked].delete peer    # just in case
    _notice "You have re-granted access to revoked user #{peer}"
  end
  @var[:user_keys][peer] = key
  content = [ AES3::iv_str(@connection.comm.keyring.default.iv),
              @connection.comm.keyring.default.key, @var[:our_name],
              @var[:pub_rsa] ]
  _remote_control(peer, :grant, content.join(' '), true)
  _save_env
  unless @var[:granted].include? peer
    @var[:granted] << peer
    _notice "You have granted access to #{peer}"
  end
end


# Deny the given user access to your chat messages, add them to your revocation
# list so you don't give them access in the future (undo with /grant), and
# rekey right now.
def local_revoke(peer)
  @var[:revoked] << peer unless @var[:revoked].include?(peer)
  _notice "You have revoked access to #{peer}"
  local_rekey('')
end  


# Request a list of names of users logged in to a given chatroom.  If no
# chatroom name is provided, the current room name will be used.
def local_names(body)
  body = @var[:room] if body.length < 1
  room_id = @connection.room_ids[body]
  raise "Invalid room name: #{body}" unless room_id
  @var[:names_requested] = true
  _server_control('names', room_id)
end


# Set or request the MOTD of the current chatroom.
def local_motd(body)
  room_name = @var[:room]
  room_hash = MD5::digest(room_name)[0,8]
  room_hash = EMPTY_ROOM if room_name == 'chat'
  _server_control('motd', room_hash + body)
end


# Ping a user explicitly.  One argument - peer's name.
def local_ping(body)
  @var[:ping_request] = Time.now
  body = @var[:our_name] unless _user_keyhash(body)
  _remote_control(body, 'ping', 'empty')
end


# Toggle auto-grant on and off
def local_auto_grant(body)
  @var[:auto_grant] = !@var[:auto_grant]
  _save_env
  _notice "You have turned auto grant #{@var[:auto_grant] ? 'on' : 'off'}.",
          :notice
end


# Toggle auto-connect on and off
def local_auto_connect(body)
  @var[:auto_connect] = !@var[:auto_connect]
  _save_env
  _notice "You have turned auto connect #{@var[:auto_connect] ? 'on' : 'off'}."
end


# Exit chat; no arguments.
def local_quit(body)
  ### send notice of disconnection?
  Kernel.exit
end


# Set an away message with the other users, not with the server.  Supply
# arguments to set an away message, no arguments to return.
def local_away(body)
  if body.length > 0
    @var[:away] = body
    _remote_control(nil, 'pong', "away #{body}")
    #@var[:presence][@connection.comm.our_keyhash] = [ 'away', body ]
  else
    local_back('')
  end
end


# Declare that you are back, optionally specify a greeting.
def local_back(body)
  return nil unless @var.delete(:away)
  _remote_control(nil, 'pong', "online #{body}")
  #@var[:presence][@connection.comm.our_keyhash] = [ 'online', body ]
end


# Send a private message to another user.  This message will not be encrypted
# with AES - it will be encrypted entirely with the recipient's public RSA
# key.  If the recipient is not currently logged in, the server will hold
# the message on behalf of the recipient until he next logs in.
def local_msg(body)
  peer = _pop_token(body)
  return nil if body.length < 1
  key = @connection.comm.rsa_keys[peer]
  raise "invalid user: #{peer}" unless key
  _remote_control(peer, :msg, body, true)
end


# Join a chat room - one argument.
def local_join(body)
  room = body.dup.sub('@', '')
  return nil unless room.length >= 1
  room_hash = MD5::digest(room)[0,8]
  room_hash = EMPTY_ROOM if room == 'chat'
  @connection.room_names[room_hash] = room
  @connection.room_ids[room] = room_hash
  _remote_control(@var[:our_name], :invite, body, true)
  _server_control('join', room_hash)
  local_switch(room.dup)
end


# Leave a chat room - one argument.
def local_leave(body)
  room = body.dup
  room = @var[:room] unless room.length >= 1
  room_hash = MD5::digest(room)[0,8]
  room_hash = EMPTY_ROOM if room == 'chat'
  unless room == 'chat'
    @connection.room_names.delete(room_hash)
    @connection.room_ids.delete(room)
  end
  _server_control('leave', room_hash)
  local_switch('chat')
end


# Switch to speaking in the given chatroom.  If no room is given, the main
# room will be selected.  Private messaging can be accomplished by prepending
# a '@' character to the user's name.
def local_switch(body, prevent = false)
  room = body
  room = 'chat' if room.length < 1
  unless @connection.room_ids[room] or room == 'chat' or room[0,1] == '@'
    _notice "You are not in room '#{room}'", :error
    return nil
  end
  @var[:room] = room
  unless prevent
    if room[0,1] == '@'
      _notice "You are now private messaging with #{room[1..-1]}.", room
    else
      _notice "You are now chatting in '#{room}'", room
    end
  end
end


# Generate a new private AES key and sent it to all of our currently
# connected, trusted friends.
def local_rekey(body)
  @connection.comm.keyring.rekey!
  @var[:granted].each do |peer|
    local_grant(peer) unless @var[:revoked].include?(peer)
  end
  _notice "New symmetric key generated " +
          "(#{AES3::iv_str(@connection.comm.keyring.default.iv)}).", :crypto
end


# A user is logging in.  Maybe it's us!
def remote_name(sender, body)
  params = body.split
  return nil unless params.length == 2 and params.first =~ /[0-9a-f]+:[0-9a-f]+/
  local_rekey('')
  key_hash = MD5::digest(params.first)[0,8]
  fingerprint = _fingerprint(key_hash)
  if key_hash == @connection.comm.our_keyhash
    if @var[:logged_in]
      _notice "Your account has connected from another location.", :notice
      @var[:logged_in] += 1
      local_grant(_user_name(key_hash))
    else
      _notice "Connected to #{@var[:last_connection].join(':')}.", :global
      @var[:logged_in] = 1
    end
  else
    # Try to log in the user by their key first
    name = _user_name(key_hash)
    if name != 'unknown_user'
      unless @var[:presence][key_hash]
        @var[:presence][key_hash] = [ 'online', '' ]
        _notice "Trusted user #{name} has connected.", 'chat'
      end
      local_grant(name) unless @var[:revoked].include?(name)
      return nil
    end

    # Detect someone signing on with a new key and an old name (spoofing)
    if @connection.comm.rsa_keys[params.last] and
       @connection.comm.rsa_keys[params.last] != params.first

      # User spoofing has been detected.  Give the user a temporary name.
      tmp_name = "fake_#{params.last}"
      tmp_name += ("_%02x" % rand(256)) if @connection.comm.rsa_keys[tmp_name]
      add_error("User spoofing detected!  #{params.last} tried to sign on " +
                "with an invalid key (#{fingerprint}). Renaming to #{tmp_name}")
      params << tmp_name
    end

    # Whether spoofing has been detected or not, let's give the person a
    # name and a key entry.
    name = params.last
    @connection.comm.rsa_keys[name] = params.first
    @connection.comm.names[key_hash] = name
    if params.length == 2
      _notice "Someone claiming to be #{name} has connected (#{fingerprint})",
              'chat'
    end

    # Should we auto-grant them?
    unless @var[:revoked].include?(name)
      local_grant(name) if @var[:auto_grant]
    end
  end
end


# A remote user has granted us their AES key!  Let's add it to our keyring.
# Format: "grant" <aes_iv_str> <aes_key> <peer_name> <peer_rsa_key>
def remote_grant(sender, body)
  key_id  = AES3::iv_from_str(_pop_token(body))
  aes_key = _pop_token(body)
  peer    = _pop_token(body)
  rsa_key = _pop_token(body)
  key_hash = MD5::digest(rsa_key)[0,8]

  # Remote user's data/presence
  fingerprint = _fingerprint(key_hash)
  _adjust_presence('online', key_hash, EMPTY_ROOM, '', false)
  _adjust_presence('join',   key_hash, EMPTY_ROOM, '', false)

  # Are we getting an AES key from another instance of our account?
  if key_hash == @connection.comm.our_keyhash
    unless @connection.comm.keyring.ring[key_id]
      local_grant(sender)
      @connection.comm.keyring.add_key(key_id, aes_key)
    end
    return nil
  end
  @connection.comm.keyring.add_key(key_id, aes_key)

  # Are we getting this key from a trusted user?
  if _user_keyhash(sender)
    if _user_keyhash(sender) != key_hash

      # Calculate the keyhash we have for this user
      known = _fingerprint(_user_keyhash(sender))

      # Give the suspicious remote user a suspicious-sounding name
      tmp_name = "fake_#{sender}"
      tmp_name += ("_%02x" % rand(256)) if @connection.comm.rsa_keys[tmp_name]
      _notice("User #{sender} (claiming to be #{peer}) has sent you a " +
              "public key you don't recognize.  Fingerprint is " +
              "(#{fingerprint}), expected (#{known}).  Renaming this user " +
              "to #{tmp_name}", :notice)
      sender = tmp_name
    end
    peer = sender
    unless @var[:granted_by].include? peer
      _notice("You were granted access by trusted user #{peer} " +
              "(#{fingerprint})", :crypto)
      @var[:granted_by] << peer
    end

    # Grant th is trusted user our key unless we've already given it to him
    # or we have placed him on our revoked list
    unless @var[:granted].include?(peer) or @var[:revoked].include?(peer)
      local_grant(peer)
    end

  # We don't know exactly who sent us this key, do we?
  else
    # Wait a minute, does this "new" user have a name we know?  That's weird!
    # Give the suspicious remote user a suspicious-sounding name!
    if @connection.comm.rsa_keys[peer]
      known = _fingerprint(_user_keyhash(peer))
      tmp_name = "fake_#{peer}"
      tmp_name += ("_%02x" % rand(256)) if @connection.comm.rsa_keys[tmp_name]
      _notice("'New' user claiming to be #{peer} has sent you a " +
              "public key you don't recognize.  Fingerprint is " +
              "(#{fingerprint}), expected (#{known}).  Renaming this user " +
              "to #{tmp_name}", :notice)
      peer = tmp_name
    end

    # Add their key (we'll take keys from anyone) and reciprocate if needed.
    @connection.comm.rsa_keys[peer] = rsa_key
    @connection.comm.names[key_hash] = peer
    _notice "You were granted access by new user #{peer} (#{fingerprint})"
    unless @var[:granted].include?(peer) or @var[:revoked].include?(peer)
      local_grant(peer) if @var[:auto_grant]
    end
  end
end


# We've received a keepalive from the server.  Woo friggin' hoo.
def remote_keepalive(sender, body)
end


# We're receiving an MOTD for the given room.
def remote_motd(sender, body)
  return nil unless sender == 'server'
  room = @connection.room_names[body[0,8]]
  username = _user_name(body[8,8])
  body[0,16] = ''
  _notice "-- #{body} (#{username}) --", room
end


# We've received a list of keyhashes from the server for a given room.
def remote_names(sender, body)
  return nil unless sender == 'server'
  room = @connection.room_names[body[0,8]]
  body[0,8] = ''
  key_hashes = []
  while body.length >= 8 do
    key_hashes << body[0,8]
    body[0,8] = ''
  end

  # Print the names if explicitly requested
  if @var.delete(:names_requested)
    _notice("#{room}: #{key_hashes.collect { |x| _user_name(x) }.join('  ')}",
            room)
  end
  
  # Quietly update presence state
  @var[:membership][room] = []
  key_hashes.each do |kh|
    _adjust_presence('join', kh, room, '', false)
    # request salutation and status silently for each user?
  end
end


# Display a notice message, print the sender's name if not from the server
def remote_notice(sender, body)
  if sender == 'server'
    sender = ''
  else
    sender = "#{sender} "
  end
  _notice "#{sender}#{body}", :notice
end


# A user is joining a chatroom, leaving a chatroom, going away, or coming back.
# Always from server.  Format: operation SPACE peer{8} room{8} [ reason ]
def remote_presence(sender, body)
  raise "Attempted presense attack from #{sender}" if sender != 'server'
  operation = _pop_token(body)
  peer = body[0,8]
  room = @connection.room_names[body[8,8]]
  msg = body[16..-1]
  _adjust_presence(operation, peer, room, msg, true)
end


# A user has sent us a private message.  Here the message is already decrypted
def remote_msg(sender, body)
  add_msg("|#{sender}| #{body}", :notice)
end


# A user has invited us to join a chatroom.  Maybe it's us.
def remote_invite(sender, body)
  room_hash = MD5::digest(body)[0,8]
  @connection.room_names[room_hash] = body
  @connection.room_ids[body] = room_hash
  if _user_keyhash(sender) != @connection.comm.our_keyhash
    _notice "You have been invited by #{sender} to join #{body}.", :notice
  end
end


# A remote ping is a status request.  Let's tell 'em where and what we be.
def remote_ping(sender, body)
  _notice "PING?/PONG! (#{sender})", :notice
  _remote_control(sender, 'pong',
                  @var[:presence][@connection.comm.our_keyhash].join(' '))
end


# A user has sent us their status information; it may have been requested.
# Format: presence SPACE salutation
def remote_pong(sender, body)
  presence = _pop_token(body)
  req = @var.delete :ping_request
  if req
    _notice("Ping reply from #{sender}: #{((Time.now - req) * 1000).to_i}ms",
            :notice)
  end
  if [ 'online', 'away' ].include?(presence)
    _adjust_presence(presence, _user_keyhash(sender), '', body, true)
  end
end


# The chat client is starting up!
def event_startup()
  require 'md5'

  # Generate a random AES session key first thing
  @connection.comm.keyring.rekey!

  # Set our defaults and then load our environment variables
  @var[:last_connection] = [ 'chat30.no-ip.org', 9000 ]
  @var[:auto_grant] = true          # We automatically give our key to new users
  @var[:auto_connect] = true        # We should connect on startup by default
  @var[:user_keys] = {}             # Maps usernames to full public keys
  @var[:last_ping] = Time.now       # Reset our ping counter
  @var[:timestamp] = "(%H:%M) "     # Default chat timestamp
  _load_env                         # Load previous environment variables

  # Upgrades!  Check to see if the version in env3.yml is less than the
  # version of this file.
  #####################################################################
  if _versioncmp(@var[:version], '3.0.1') < 0
    @var[:timestamp] = "(%H:%M) "   # fixed missing timestamp in 3.0.1
  end
  if @var[:version] != _version()
    @var[:version] = _version()
    _save_env
  end

  # This is where we load the user's public and private key from the env.yml
  # configuration file.  If it's not there, we spawn a helpful creation tool.
  # This tool MUST return public key, private key, and user-name.
  unless @var[:our_name] and @var[:pub_rsa] and @var[:prv_rsa]
    @var[:our_name], @var[:pub_rsa], @var[:prv_rsa] = keygen_tool()
    if @var[:our_name] and @var[:prv_rsa].to_s =~ /[0-9a-f]+:[0-9a-f]+/ and
       @var[:pub_rsa].to_s =~ /[0-9a-f]+:[0-9a-f]+/
      _save_env
    else
      add_error("YOU HAVE NO KEYS!  TOOL MUST BE CALLED.")
      Kernel.exit(0)
    end
  end
  @connection.comm.initialize_address_book(@var[:pub_rsa], @var[:prv_rsa],
                                           @var[:our_name])

  # Initialize a blacklist of environment variables we don't want saved
  @var[:blacklist_env] = Array.new
  @var[:blacklist_env].push :blacklist_env
  @var[:blacklist_env].push :script_lines
  @var[:blacklist_env].push :file_open_raised
  @var[:blacklist_env].push :last_private_peer
  @var[:blacklist_env].push :private_user
  @var[:blacklist_env].push :granted
  @var[:blacklist_env].push :granted_by
  @var[:blacklist_env].push :room
  @var[:blacklist_env].push :away
  @var[:blacklist_env].push :logged_in
  @var[:blacklist_env].push :membership
  @var[:blacklist_env].push :presence
  @var[:blacklist_env].push :ping_request

  _network_init

  # Startup the timer thread
  Thread.new do
    loop do
      sleep 15
      dispatch :timer
    end
  end

  # Auto-connect?
  local_connect('') if @var[:auto_connect]
end


# Every few seconds, call this timer function for general housekeeping
def event_timer
  if @connection.comm.connected? and Time.now - @var[:last_ping] >= 60
    begin
      _server_control("keepalive")
    rescue
      _notice("The connection to the server has been lost", :global)
      @connection.disconnect
    end
  end
end


# This event gets raised every time the user sends a broadcast message
# msg.replace() changes the message, setting it to '' precludes delivery.
def event_outgoing_broadcast(msg)
  local_back('') if @var[:away] and @var[:room] == 'chat'

  # Private message?
  if @var[:room][0,1] == '@'
    peer = @var[:room].sub('@', '')
    local_msg("#{peer} #{msg}")
    msg.replace('')
  end
end


# Event gets raised when receiving a broadcast message.
# msg.replace() changes the message, setting it to '' precludes delivery.
def event_incoming_broadcast(peer, room, msg)
end


# Event gets raised when a line is about to get added to the screen.
def event_display_line(msg, room)
  msg.replace("#{Time.now.strftime(@var[:timestamp])}#{msg}") if msg
end


# --------------------------------------------------------------------------
# No more definitions beyond this point
end
#### End of aggregated 'user3.rb' ####
#### Aggregator included 'guser3.rb' ####
# Copyright notice:
#  (C) 2009-2010
# This software is provided 'as-is' without any express or implied warranty.
# In no event will the authors be held liable for damages arising from the
# use of this software.  All license is reserved.


# Extensions to user3.rb specific to the Fox GUI instance.

# All definitions will be associated with this object:
class Chat3

# Put your definitions below this line:
# --------------------------------------------------------------------------


# Outgoing private messages should still get displayed to the gui
alias _guser_local_msg local_msg
def local_msg(body)
  _guser_local_msg(body.dup)
  peer = _pop_token(body)
  add_msg("#{@var[:our_name]}: #{body}", "@#{peer}")
end


# Completely overwrite private message reception.
alias _guser_remote_msg remote_msg
def remote_msg(sender, body)
  add_msg("#{sender}: #{body}", "@#{sender}")
end


# Close the GUI portion of a chat room tab as well
alias _guser_local_leave local_leave
def local_leave(body)
  body = @var[:room] if body.empty?
  raise "You cannot leave the main chatroom" if body == 'chat'
  _guser_local_leave(body) unless body[0,1] == '@'
  @window.remove_tab(body)
end


# When the user switches rooms, we need to select that tab in the GUI
alias _guser_local_switch local_switch
def local_switch(body)
  _guser_local_switch(body, true)
  @window.room_change(body)
end


# Since we have suppressed room join notifications inherent to local_switch(),
# we must manually add them back here.
alias _guser_local_join local_join
def local_join(body)
  _guser_local_join(body)
  _notice "You are now chatting in '#{body}'", body
end


# Close the current tab/room on the screen
def local_close(body)
  body = @var[:room] if body.empty?
  @window.remove_tab(body)
end


# Spawn a whiteboard window and associate it to the given chat room.
# Logic here should mirror local_join, except you can't join the main room
# and a WhiteboardPand tab is automatically created.  We also don't invite
# other instances of ourselves - that'd be weird!
def local_whiteboard(body)
  room = body.dup.sub('@', '')
  return nil unless room.length >= 1
  room_hash = MD5::digest(room)[0,8]
  raise "Can't whiteboard main room" if room == 'chat' or
                                        room_hash == EMPTY_ROOM

  # Spawn our whiteboard window
  @window.new_tab(room, WhiteboardPane)

  # Connect to the room on the network
  @connection.room_names[room_hash] = room
  @connection.room_ids[room] = room_hash
  _server_control('join', room_hash)
  local_switch(room.dup)
end


# --------------------------------------------------------------------------
# No more definitions beyond this point
end
#### End of aggregated 'guser3.rb' ####

client = Chat3.new
client.run
