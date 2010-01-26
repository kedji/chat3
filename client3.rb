# Copyright notice:
#  (C) 2009-2010
# This software is provided 'as-is' without any express or implied warranty.
# In no event will the authors be held liable for damages arising from the
# use of this software.  All license is reserved.


# Object that mediates access between the server and the local chat window.
# This object establishes connections, receives messages, and sends messages.
# Last revision:  December 3, 2009

require 'comm3.rb'

class ChatConnection

  # Takes a callback block which accepts (type, sender, room, msg)  
  def initialize(&callback)
    @comm = CryptoComm.new     # Our connection to the server
    @mutex = @comm.mutex
    @msg_callback = callback
    @room_names = { "\x00" * 8 => 'chat' }
    @room_ids = { 'chat' => "\x00" * 8 }
  end

  attr_reader :room_names, :room_ids, :comm

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
  end

  # Shut down the connection
  def disconnect
    @comm.shutdown
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
