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
  if _guser_local_switch(body, true)
    @window.room_change(body)
  end
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
  room = body.dup
  room[0,1] = '' until room[0,1] != '@'
  return nil unless room.length >= 1
  room_hash = MD5::digest(room)[0,8]
  raise "Can't whiteboard main room" if room == 'chat' or
                                        room_hash == EMPTY_ROOM

  # Spawn our whiteboard window
  @window.new_tab(room, WhiteboardPane)
  @var[:special_rooms][room] = false

  # Connect to the room on the network
  @connection.room_names[room_hash] = room
  @connection.room_ids[room] = room_hash
  _server_control('join', room_hash)
  local_switch(room.dup)
end


# Select which font/size we'd like to use.  Running with no arguments spawns a
# selection dialog.  Supply one argument to specify a font name directly, or
# two arguments to specify a font and a size.
def local_font(body)
  opts_array = [ @var[:skin][:font].dup, @var[:skin][:font_size] ]
  params = body.split

  # Should we spawn a dialog?
  if params.empty?
    chooser = FontDialogBox.new(@fox_app, opts_array)
    chooser.create
    if chooser.execute(PLACEMENT_OWNER) != 1
      return nil
    end

  # Some manual options were specified
  else
    opts_array[0] = params.first.dup
    size = params[1].to_i
    opts_array[1] = size if size >= 5
  end

  # Font options are now in opts_array
  @var[:skin][:font]      = opts_array[0]
  @var[:skin][:font_size] = opts_array[1]
  @window.apply_skin(@skin)
  _save_env
  true    
end


# Select which background color we'd like
def local_bg(body)
  opts_array = [ "background", @var[:skin][:back_color].to_i ]
  chooser = ColorDialogBox.new(@fox_app, opts_array)
  chooser.create
  if chooser.execute(PLACEMENT_OWNER) == 1
    @var[:skin][:back_color] = opts_array[1]
    @window.apply_skin(@skin)
    _save_env
  end
end


# --------------------------------------------------------------------------
# No more definitions beyond this point
end
