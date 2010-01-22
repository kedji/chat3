# Copyright notice:
#  (C) 2009-2010
# This software is provided 'as-is' without any express or implied warranty.
# In no event will the authors be held liable for damages arising from the
# use of this software.  All license is reserved.


# Communication abstraction layer for Chat 3.0 - used by both the client and
# the server.
# Last revision:  Dec 4, 2009

#FILE_DIRECTORY = (File.join(File.expand_path('~'), '.sechat') rescue '.')
FILE_DIRECTORY = '.'

require 'socket'
require 'openssl'
require 'md5'
require 'monitor'

require 'symmetric3.rb'
require 'rsa.rb'
require 'address_book.rb'


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
    @rsa_keys = RSA_ADDRESS_BOOK
    @socket = nil
    @thread = nil
    @mutex = Monitor.new    # universal, top-level mutex object

    # Build our reverse address book out of MD5 hashes
    @our_keyhash = MD5::digest(@rsa_keys[:pub])[0,8]
    @names = { @our_keyhash => @rsa_keys[:name], EMPTY_ROOM => 'server' }
    @rsa_keys.each do |n,k|
      if k.class == String && n.class == String
        @names[MD5::digest(k)[0,8]] = n
      end
    end
    @rsa_keys[@rsa_keys[:name]] = @rsa_keys[:pub]
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
              callback.call(nil, nil, nil, "could not decrypt message from " +
                            "#{sender_name(sender_hash)}")
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
              callback.call(nil, nil, nil, "could not decrypt message from " +
                            "#{sender_name(sender_hash)}")
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
              callback.call(nil, nil, nil, "could not decrypt message from " +
                            "#{sender_name(sender_hash)}")
            end
          end
        elsif type == 'P' or type == 'A'
#$stderr.puts "Got private message"
          @mutex.synchronize do
            rsa = Key.new(@rsa_keys[:prv])
            begin
              msg = rsa.decrypt(opaque)
              callback.call('C', sender_hash, nil, msg)
            rescue
              callback.call(nil, nil, nil, "could not decrypt message from " +
                            "#{sender_name(sender_hash)}")
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
