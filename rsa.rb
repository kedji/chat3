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
