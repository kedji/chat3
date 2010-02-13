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
  # A note on special_rooms.  Special rooms are "rooms" that may or may not
  # be tied to an actual chatroom, and even if they are, it may be inappropriate
  # to log their contents.  Whiteboard rooms, for instance, are connected to
  # an actual chatroom, but logging the rooms' contents would be absurd.
  # Private message "rooms" aren't actual chatrooms, but logging is probably a
  # good idea.  The special room hash persists across network restarts but is
  # not saved to disk.  Any value evaluating to true means "log".
  special_rooms = @var.delete :special_rooms

  # Flush out all blacklisted state
  @var[:blacklist_env].each { |rm| @var.delete rm unless rm == :blacklist_env }
  @var[:special_rooms] = special_rooms

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
  prior_msg = (@var[:presence][peer_keyhash] || []).last
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
      _notice "#{peer_name} has disconnected#{msg}", 'chat'
      @var[:presence].delete peer_keyhash
    elsif op == 'away' and (prior != current or status != prior_msg)
      _notice "#{peer_name} is away#{msg}", 'chat'
    elsif op == 'back' or current == 'online' and prior != current
      _notice "#{peer_name} is back#{msg}", 'chat'
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
# to nil to deliver a remote control to the whole room.  If peer is set to nil
# then the open AES key will be used, which means everyone will be able to
# decrypt your message, including the server.  If "use_rsa" is set to true and
# no user is specified, your default AES key will be used instead, which means
# only users to whom you've granted access will be able to decrypt your message.
def _remote_control(peer, command, body, use_rsa = false)
  raise "Invalid user, #{peer}" if peer and not _user_keyhash(peer)
  if peer and use_rsa
    @connection.comm.send_private_command("#{command} #{body}", peer)
  else
    peer = _user_keyhash(peer) if peer
    peer = true if not peer and use_rsa
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


# Invite the given user to the given room.  2 arguments
def local_invite(body)
  peer = _pop_token(body)
  room = @var[:room] if body.length < 2
  _remote_control(peer, :invite, room)
  _notice "#{peer} has been invited to #{room}"
end


# Display the local version - no arguments
def local_version(body)
  _notice(_version)
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


# Remove the given user's key.  Only works if the user is not logged in.
def local_remove(body)
  key_hash = _user_keyhash(body)
  raise "Invalid username" unless key_hash
  raise "That user is signed in!" if @var[:presence][key_hash]
  @connection.comm.rsa_keys.delete(body)
  @connection.comm.names.delete(key_hash)
  @var[:user_keys].delete body
  _save_env
  _notice "User '#{body}' has been removed from your key repository"
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


# Display a list of the environment variables, no arguments.
def local_env(body)
  env = ''
  vtmp = @var.dup
  vtmp[:pub_rsa] = '[PUBLIC RSA KEY]'
  vtmp[:prv_rsa] = '[PRIVATE RSA KEY]'
  vtmp[:user_keys] = @var[:user_keys].collect { |k,_| k }
  vtmp.each { |k,v| env << "#{(k.to_s + ' '*20)[0,20]} => #{v.inspect}\n" }
  _notice " -- Current Environment Variables --\n#{env}"
end


# Grant your session key to the provided user - 1 argument.
def local_grant(peer)
  key = @connection.comm.rsa_keys[peer]
  raise "invalid user: #{peer}" unless key
  if @var[:revoked].delete peer    # just in case
    _notice "You have re-granted access to revoked user #{peer}"
    @var[:granted] << peer
  end
  @var[:user_keys][peer] = key

  # Set our status to "online" if need be
  @var[:presence][@connection.comm.our_keyhash] ||= [ 'online', '' ]
  status = 'online'
  reason = @var[:presence][@connection.comm.our_keyhash].last.dup
  if @var[:presence][@connection.comm.our_keyhash].first == 'away'
    status = 'away'
  end

  # Construct the components we need to send in order
  content = [ AES3::iv_str(@connection.comm.keyring.default.iv),
              @connection.comm.keyring.default.key, @var[:our_name],
              @var[:pub_rsa], status, reason ]
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
    _remote_control(nil, 'pong', "away #{body}", true)
    #@var[:presence][@connection.comm.our_keyhash] = [ 'away', body ]
  else
    local_back('')
  end
end


# Declare that you are back, optionally specify a greeting.
def local_back(body)
  return nil unless @var.delete(:away)
  _remote_control(nil, 'pong', "online #{body}", true)
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
  room = body.dup
  room[0,1] = '' until room[0,1] != '@'
  return nil unless room.length >= 1
  unless @var[:special_rooms].include?(room)
    room_hash = MD5::digest(room)[0,8]
    room_hash = EMPTY_ROOM if room == 'chat'
    @connection.room_names[room_hash] = room
    @connection.room_ids[room] = room_hash
    _remote_control(@var[:our_name], :invite, body, true)
    _server_control('join', room_hash)
  end
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
# a '@' character to the user's name.  Return true on success, false otherwise.
def local_switch(body, prevent = false)
  room = body
  room = 'chat' if room.length < 1
  unless @connection.room_ids[room] or room == 'chat' or room[0,1] == '@' or
         @var[:special_rooms].include?(room)
    _notice "You are not in room '#{room}'", :error
    return false
  end
  @var[:room] = room
  unless prevent
    if room[0,1] == '@'
      _notice "You are now private messaging with #{room[1..-1]}.", room
    else
      _notice "You are now chatting in '#{room}'", room
    end
  end
  true
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
      _notice "Your account has connected from another location.", 'chat'
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
        if @var[:revoked].include?(name)
          _notice "Revoked user #{name} has connected.", 'chat'
        else
          _notice "Trusted user #{name} has connected.", 'chat'
          local_grant(name)
        end
      end
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
# Format: "grant" <aes_iv_str> <aes_key> <peer_name> <peer_rsa_key> <status>
def remote_grant(sender, body)
  key_id  = AES3::iv_from_str(_pop_token(body))
  aes_key = _pop_token(body)
  peer    = _pop_token(body)
  rsa_key = _pop_token(body)
  status  = _pop_token(body).to_s
  status  = 'online' if status.length < 3
  key_hash = MD5::digest(rsa_key)[0,8]

  # Remote user's data/presence
  fingerprint = _fingerprint(key_hash)
  _adjust_presence(status, key_hash, EMPTY_ROOM, body, false)
  _adjust_presence('join',   key_hash, EMPTY_ROOM, body, false)

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
  _notice "-- MOTD (#{username}) --\n#{body}", room
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
    _notice("-- Users on #{room}: --\n" + 
            "#{key_hashes.collect { |x| _user_name(x) }.join('  ')}", room)
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


# This actuall gets called BEFORE startup.  The environment variables have
# to be read before the GUI can be drawn, since the GUI depends on the
# environment variables.
def event_initialize_environment()

  # Set our defaults and then load our environment variables
  @var[:last_connection] = [ 'chat30.no-ip.org', 9000 ]
  @var[:auto_grant] = true          # We automatically give our key to new users
  @var[:auto_connect] = true        # We should connect on startup by default
  @var[:user_keys] = {}             # Maps usernames to full public keys
  @var[:last_ping] = Time.now       # Reset our ping counter
  @var[:timestamp] = "(%H:%M) "     # Default chat timestamp
  @var[:special_rooms] = {}         # Don't save these, may not be actual rooms
  _load_env                         # Load previous environment variables

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
  @var[:blacklist_env].push :special_rooms
  @var[:blacklist_env].push :away
  @var[:blacklist_env].push :logged_in
  @var[:blacklist_env].push :membership
  @var[:blacklist_env].push :presence
  @var[:blacklist_env].push :ping_request

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
end


# The chat client is starting up!  At this point, the GUI is already displayed
# and the environment variables are already loaded.
def event_startup()
  require 'md5'

  # Generate a random AES session key first thing
  @connection.comm.keyring.rekey!

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
