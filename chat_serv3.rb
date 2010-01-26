#!/usr/bin/env ruby

# Copyright notice:
#  (C) 2009-2010
# This software is provided 'as-is' without any express or implied warranty.
# In no event will the authors be held liable for damages arising from the
# use of this software.  All license is reserved.


# This is the new and improved Chat 3.0 server.  Once again we're using
# OpenSSL (although we don't depend on it for authentication or
# confidentiality).  Massive code copies from 2.x, but care has been taken
# to keep things as minimalist as possible.
# Last revison:  June 22, 2009

$LOAD_PATH.unshift File.dirname(__FILE__)
require 'comm3.rb'
$LOAD_PATH.unshift FILE_DIRECTORY

require 'serv_ssl.rb'
require 'symmetric3.rb'

class ClientConnection

  def initialize(socket, owner)
    @owner = owner
    @name = nil               # For chat 3.0, 8 bytes of pub key (in hex)
    @socket = socket          # The actual communication socket
    @buff = String.new        # intra-message buffer
    @var = Hash.new           # plugin variables go here
    @enc = nil                # encryption key (for outgoing messages)
    @dec = nil                # decryption key (for incoming messages)
    @blocks = nil             # Number of blocks to read before we decrypt
    @type = nil               # Type of the incoming message
    @keyring = owner.keyring  # Only holds our own AES key
  end
  attr_accessor :name, :socket, :buff, :var

  # This client has sent some data.  Receive it, and return the message
  # if complete.  Return nil if no data, true if incomplete data, otherwise...
  # Returns [ type, sender_hash, key_id, opaque ]
  def recv
    bufflen = @buff.length
    unless @name  # haven't received a key yet - only accept keys
      if @buff.length < 5
        @buff << @socket.readpartial(5 - @buff.length)
        return nil if bufflen == @buff.length
        return true
      end

      # The first message gets sent to key_setup()
      len = (@buff[1] << 24) + (@buff[2] << 16) + (@buff[3] << 8) +
            @buff[4] + 21
      raise "invalid crypt-init" if len > 16008 || @buff[0] != MSG_SERVER
      @buff << @socket.readpartial(len - @buff.length)
      if @buff.length == len
        key_setup(@buff[5,8], @buff[13,8], @buff[21..-1])   # sets @name
        ret = @buff
        @buff = String.new
        return [ ret[0], ret[5,8], ret[13,8], ret[21..-1] ]
      end
      return nil if bufflen == @buff.length
      return true
    end  # Okay, key exchange has completed.  Go ahead

    # First make sure we get the message header
    unless @blocks
      @buff << @socket.readpartial(21 - @buff.length)
      if @buff.length == 21
        @blocks = (@buff[1] << 24) + (@buff[2] << 16) + (@buff[3] << 8) +
                  @buff[4] + 21
        raise "account spoof detected" unless @buff[5,8] == @name
        raise "invalid msg length" if @blocks == 0 or @blocks > MSG_MAXIMUM
      end
      return nil if bufflen == @buff.length
      return true
    end

    # Now get the body of the message
    @buff << @socket.readpartial(@blocks - @buff.length)
    if @buff.length == @blocks
      ret = [ @buff[0], @buff[5,8], @buff[13,8], @buff[21..-1] ]
      @buff, @blocks = '', nil
      return ret
    end
    return nil if bufflen == @buff.length
    return true
  end

  # Register and psuedo-authenticate a new user
  def key_setup(name, key_id, msg)
    login_info = @keyring.decrypt(key_id, msg).split
    if login_info.length != 3 || name != MD5::digest(login_info[1])[0,8] ||
       (login_info[1] =~ /[0-9a-f]+:[0-9a-f]+/) != 0 || login_info[0] != 'name'
      raise "Invalid login message"
    end
    @name = name
    unless @owner.rooms[EMPTY_ROOM].include?(@name)
      @owner.rooms[EMPTY_ROOM] << @name
    end
    @owner.select_send(MSG_SERVER, name, key_id, msg) { |x| x.name }

    # Deliver any stored private messages
    @owner.private_queue.each do |k,m|
      send(m) if k == name
    end
    @owner.private_queue.reject! { |k,_| k == name }
  end

  # Send a message straight up
  def send(data)
    @socket.print(data)
  end
  
end  # of class Client Connection

  
# Class which manages an instance of the extensible chat server
class ChatServer

  # Class method which instantiates an object and starts the server
  def self.run(*port)
    new(*port).serve
  end

  def initialize(*port)
    @port = port[0] || 9000
    serv_ssl = ServerSSL.new
    @listen_socket = serv_ssl.new_server('0.0.0.0', @port.to_i)
    #@listen_socket = TCPServer.new('0.0.0.0', @port.to_i)
    @clients = Hash.new
    @rooms = { "\x00" * 8 => [] }
    @motd = { }
    @cmds = Array.new      # Server plugins go here
    @var = Hash.new        # Plugin variables go here
    @keyring = Keyring.new
    @private_queue = []    # saved private messages
    load_command_methods(:kill)  # kill in this context means "exit on error"
  end

  attr_reader :rooms, :keyring, :private_queue

  # Run until we've been signaled to shut down
  def serve
    # Set SIG-HUP to re-read the controls.rb file
    trap "HUP" do
      dispatch :sighup
    end

    # Set SIG-INT to send out notification of a shutdown, then shut down
    trap "INT" do
      _notice(nil, "Server is shutting down VERY SOON!")
      puts "Notifaction sent.  Press Ctrl-C once more to exit."
      dispatch :log, "Notifaction of shutdown sent."

      # Now redifine this signal handler to actually shut down.
      trap "INT" do
        @clients.each { |sock,_| kill_client(sock, "Server has shut down.") }
        dispatch :log, "Shutdown"
        Kernel.exit
      end
    end

    # Do some last minute prep
    epoch = Time.now   # Keep track of how long it's been since last time.
    dispatch(:startup)

    # Start serving
    begin

      # Find out which sockets have pending data
      sockets = @clients.collect { |sock,_| sock }
      sockets << @listen_socket

      # SSL sockets buffer, so they don't work with select() completely.
      # First manually check for available read data using .pending(), then
      # call select() only when nothing is pending.
      readable = []
      @clients.collect { |sock,_| readable << sock if sock.pending > 0 }

      # Call select if nothing was buffered
      if readable.empty?
        ready = (select(sockets, nil, sockets, 90) || [])
        readable = (ready[0] || [])
        errored = (ready[2] || [])
      end

      # Do we have any new connections?
      if readable.include? @listen_socket
        accept_connection()
        readable.delete @listen_socket
      end

      # Do we have any connections that have errored out?
      prune_sockets(errored)
      
      # Take all of our readable sockets, and read their data
      read_sockets(readable)

      # Call our periodic function if enough time has passed
      if Time.now - epoch > 60
        dispatch(:epoch)
        epoch = Time.now
      end

    end while not @listen_socket.closed?
  end  # of serve()

  # @listen_socket has a new connection for us
  def accept_connection
    begin
      sock = @listen_socket.accept
      @clients[sock] = ClientConnection.new(sock, self)
      dispatch :new_connection, @clients[sock]
    rescue
      @clients.delete sock rescue nil
    end
  end

  # Trim out the sockets that have generated system-level errors
  def prune_sockets(errored)
    errored.delete @listen_socket  # just in case

    # Remove the clients and get a list of removed clients' names
    errored.collect! { |sock| @clients.delete(sock).name rescue nil }
    errored.delete nil
    errored.each { |name| dispatch :connection_reset, name, "reset by client" }
  end

  # Loops through all sockets that had data and reads what we have
  def read_sockets(readable)
    non_empty = true
    non_empty = false
    readable.each do |sock|

      # First read from the given client
      begin
        type, sender, key_id, opaque = @clients[sock].recv
        non_empty = true if type
      rescue
        dispatch(:exception, $!.to_s) unless $!.to_s == "end of file reached"
        client = @clients.delete(sock)
        dispatch :connection_reset, client, "goodbye" if client.name
        sock.close
        next
      end

      # If we have received the whole message
      if opaque
        begin
          if sender != @clients[sock].name
            raise "Spoofing of user #{@clients[sock].name.inspect} by" +
                   " #{sender.inspect} detected!"
          end
          new_message(type, sender, key_id, opaque, sock)

        # if any exceptions are raised, kill the offending client
        rescue
          dispatch(:exception, "#{$!} >> #{$@.join('--')}")
          kick_client(sock, $!)
        end

      end  # of msg
    end  # of each socket
  end  # of readable

  # A client comitted some offense.  Tell them (if they're still connected),
  # then kick them off the server.
  def kick_client(sock, reason)
    name = @clients.delete(sock)
    dispatch(:connection_reset, name, reason) if name.name
    sock.close
  end

  # End a client connection and tell them why.  No events, no notification
  # of others.
  def kill_client(sock, reason = nil)
    @clients.delete sock
    sock.close
  end

  # Dispatch an event.  Guarantee synchronization (currently not needed)
  # and proper exception handling.
  def dispatch(cmd, *args)
    begin
      self.send('event_' + cmd.to_s, *args)
    rescue
      unless cmd.to_sym == :exception
        dispatch(:exception, "Event (#{cmd}) error: #{$!}\n#{$@.join("\n")}") 
      end
    end
  end
  
  # Handle a new incoming message
  def new_message(type, sender_hash, key_id, opaque, sock)
    if type == MSG_SERVER  # this is for us
      msg = @keyring.decrypt(key_id, opaque)
      indx = msg.index(' ') || msg.length
      cmd = msg[0...indx]
      msg[0..indx] = ''
      self.send("server_#{cmd}", @clients[sock], msg) if @cmds.include?(cmd)
    else
      forward_message(type, sender_hash, key_id, opaque)
    end  # of if-msg-for-server
  end  # of new_message
  
  # Encrypt a message with the server's AES key
  def server_encrypt(plain)
    @keyring.encrypt(plain)
  end

  # Forward a message along to the specified recipients, select-style
  def select_send(type, sender_hash, key_id, opaque, &ss)
    # First construct the message
    len = opaque.length
    len = (len >> 24).chr + ((len >> 16) & 0xFF).chr +
          ((len >> 8) & 0xFF).chr + (len & 0xFF).chr
    msg = type.chr << len << sender_hash << key_id << opaque

    # To whom should we forward?
    @clients.select { |_,x| ss.call(x) }.each { |_,x| x.send(msg) }.length
  end

  # Forward a message to everone, unless a recipient is specified.
  def forward_message(type, sender_hash, key_id, opaque)
    # First construct the message
    len = opaque.length
    len = (len >> 24).chr + ((len >> 16) & 0xFF).chr +
          ((len >> 8) & 0xFF).chr + (len & 0xFF).chr
    msg = type.chr << len << sender_hash << key_id << opaque
    rcpt = 0

    # Forward to one or to all?
    @clients.each do |_,v|
      # Only send to members of our chat room
      if type == MSG_BROADCAST
        room_id = opaque[0,8]
        v.send(msg) if @rooms[room_id] and @rooms[room_id].include?(v.name)

      # This is a control - is it to everyone?
      elsif type == MSG_COMMAND
        v.send(msg) if key_id == @keyring.open_key.iv || opaque[0,8] == v.name
      
      # Only send to the specified user
      else
        if v.name == key_id
          v.send(msg)
          rcpt += 1
        end
      end
    end  # of each client

    # If this is a private message that didn't get delivered, buffer it.
    if type == MSG_PRIVATE and rcpt == 0
      @private_queue << [ key_id, msg ]
    end
  end  # of forward_message

  # Load control handlers (server plugins) from controls.rb
  def load_command_methods(*args)
    begin
      # Add all the newly-defined methods to our call list
      mlist = self.methods     # Get the current list of methods
      load 'controls3.rb'      # install the user-defined methods
      @cmds += self.methods.select { |m| m.include? 'server_' and
                                           not mlist.include? m }

      # Find, translate and add any new user commands
      @cmds.collect! { |cmd| cmd.sub 'server_', '' }

    rescue SyntaxError
      if args[0] == :kill
        puts "Error loading controls3.rb: #{$!}"
        Kernel.exit
      end
      dispatch :exception, "Plugins in controls.rb could not be loaded (#{$!})."
    end
  end

end  # of ChatServer


ChatServer::run ARGV[0]
