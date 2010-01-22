# Copyright notice:
#  (C) 2009-2010
# This software is provided 'as-is' without any express or implied warranty.
# In no event will the authors be held liable for damages arising from the
# use of this software.  All license is reserved.


# Define server control handlers inside this file.  They will get defined at
# RUN TIME.  Any method you insert here will be able to respond to
# control commands from the clients.  All methods here should accept
# a client and an array param, eg:  def my_method(client, *args).  Raise
# exceptions to exit gracefully.  client will be of type ClientConnection.
#
# Prepend "server_" to method definitions
# Prepend "_" to helper methods
# Events will begin with "event_"
#
# Useful internal methods:
#   client.send_error(msg)           - send an error message to this client
#   client.send_control(cmd, *args)  - send any control with any args
#   client.spoof_control(cmd, *args) - send control but spoof the source
#   client.send_binary_control(cmd, bin)
#   send_notice(msg)                 - notify everyone of this message
#   broadcast_control(cmd, *args)    - send any control to everyone
#
# Useful internal variables:
#   @var                   - a hash where you can story any variable you like
#                            (please use :symbols)
#   client.var             - similar variable hash on client-granularity
#   @clients               - hash of sockets to ClientConnection objects
#


# All definitions will be associated with this object:
class ChatServer

# Put your definitions below this line:
# --------------------------------------------------------------------------


# Send a notice to everyone
def _notice(from_hash, m)
  from_hash ||= EMPTY_ROOM
  select_send(MSG_SERVER, from_hash, @keyring.default.iv,
              server_encrypt("notice #{m}")) { |x| x.name }
end

# Keepalive traffice to keep the connections from getting killed by shitty
# stateful firewalls
def server_keepalive(client, body)
  client.var[:last_ping] = Time.now
  select_send(MSG_SERVER, EMPTY_ROOM, @keyring.default.iv,
              server_encrypt("keepalive")) { |x| x == client }
end

# A user is requesting a list of users present in the given room
def server_names(client, body)
  unless (@rooms[body] || []).include?(client.name)
    select_send(MSG_SERVER, EMPTY_ROOM, @keyring.default.iv,
                server_encrypt("notice You are not in that room.")
               ) { |x| x == client }
    return nil
  end
  select_send(MSG_SERVER, EMPTY_ROOM, @keyring.default.iv,
              server_encrypt("names #{body}#{@rooms[body].join('')}")
             ) { |x| x == client }
end  

# A user is joining a chatroom.  Notify everyone.
def server_join(client, body)
  @rooms[body] ||= []
  return nil if @rooms[body].include?(client.name) or body.length != 8
  select_send(MSG_SERVER, EMPTY_ROOM, @keyring.default.iv,
              server_encrypt("presence join #{client.name}#{body}")
             ) { |x| @rooms[body].include?(x.name) }
  @rooms[body] << client.name
end

# A user is leaving a chatroom.  Notify everyone.
def server_leave(client, body)
  return nil unless @rooms[body]
  return nil unless @rooms[body].include?(client.name)
  @rooms[body].delete client.name
  select_send(MSG_SERVER, EMPTY_ROOM, @keyring.default.iv,
              server_encrypt("presence leave #{client.name}#{body}")
             ) { |x| @rooms[body].include?(x.name) }
  @rooms.delete body if @rooms[body].empty?
end

# A user has disconnected or has been disconnected
def event_connection_reset(client, msg)
  # Don't send out this notification if they're connected elsewhere
  return nil unless @clients.select do |_,c|
    c.name == client.name and c != client
  end.empty?
  select_send(MSG_SERVER, EMPTY_ROOM, @keyring.default.iv,
              server_encrypt("presence offline #{client.name}" +
                             "12345678#{msg}")
             ) { |x| x.name }

  # Remove this user from any rooms they may be connected to.
  @rooms.each { |_,list| list.reject! { |x| x == client.name } }
end

# The server is starting up
def event_startup()
  @var[:start_time] = Time.now

  # Log the startup
  dispatch :log, "Server startup (#{@port})"
end

# An epoch has occured (at least one minute and at most 15 minutes have passed
# since the last).
def event_epoch()
  # Flush out idle clients, if any
  @clients.each do |_,client|
    if Time.now - client.var[:last_ping] > 300
      client.socket.close
      client = @clients.delete(client.socket)
      dispatch :connection_reset, client, "ping timeout"
    end
  end
end

# A new connection has been established
def event_new_connection(client)
  client.var[:last_ping] = Time.now   # Initialize ping-timeout variable
end

# An exception was raised.  DO NOT invoke any other event handlers, or call
# functions that may.  Infinite loops may result.
def event_exception(error_str)
  unless error_str.to_s.include?('Connection reset by peer') or
         error_str.to_s.include?('Connection timed out')
    event_log "Exception: #{error_str}"
  end
end

# Write a line to the logfile.
def event_log(msg)
  time = Time.now.strftime("%h %d %H:%M:%S")
$stdout.puts "LOG: #{msg}"
#  _open_sefile('server.log', 'a') { |f| f.puts "(#{time}) #{msg}" } rescue nil
end

# We received a SIG-HUP
def event_sighup()
  _load_registrations
  load_command_methods
  dispatch :log, "SIG-HUP, controls.rb reloaded"
end


#################



# An incoming server control has been received from a client.
def event_incoming_server_control(client, cmd, *args)
  whitelist = ['nick', 'logon', 'ping']
  cmd.replace "(no username)" unless client.name or whitelist.include? cmd
end


# An incoming chat message has been received
def event_incoming_chat(client, msg)
end


# An incoming client control has been received
def event_incoming_client_control(client, peer, cmd, *args)
end


# An incoming client control that is to be broadcast to everyone
def event_incoming_clients_control(client, cmd, *args)
end




# --------------------------------------------------------------------------
# No more definitions beyond this point
end
