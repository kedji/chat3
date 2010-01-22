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
  _guser_local_leave(body) unless body[0,1] == '@'
  @window.remove_tab(body)
end


# When the user switches rooms, we need to select that tab in the GUI
alias _guser_local_switch local_switch
def local_switch(body)
  _guser_local_switch(body, true)
  @window.room_change(body)
end


# --------------------------------------------------------------------------
# No more definitions beyond this point
end
