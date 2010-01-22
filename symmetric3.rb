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
