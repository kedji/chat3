#!/usr/bin/env ruby

# Copyright notice:
#  (C) 2009-2010
# This software is provided 'as-is' without any express or implied warranty.
# In no event will the authors be held liable for damages arising from the
# use of this software.  All license is reserved.


$LOAD_PATH.push File.dirname(__FILE__)
require 'client3.rb'
$LOAD_PATH.push FILE_DIRECTORY
require 'chat_window.rb'

# Ruby tool used to grab the source of included files, not just their content
SCRIPT_LINES__ = {}

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
    dispatch(:startup)
  end

  def connect(addr, port)
    @connection.connect(addr, port.to_i)
  end

  def run
    @fox_app.create
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
          add_error("remote command from #{sender} (#{cmd}) failed: #{$!}\n" +
                    "#{$@.join("\n")}")
        end
      else
        add_error "received invalid control from #{sender}: '#{cmd}'"
      end
    end
  end

  # We've received a chat message
  def remote_chat(sender, room, msg)
    @window.room_append(room, "#{sender}: #{msg}")
    add_msg "<#{room || 'unknown'}> #{sender}: #{msg}"
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
    msg.strip!
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
            add_error("local command '#{cmd}' generated an exception: #{$!}\n#{$@.join("\n")}")
          end
        else
          add_error "invalid local command: '#{cmd}'"
        end
      end
    elsif msg.length > 0
      dispatch :outgoing_broadcast, msg
      @connection.chat_msg(msg, @var[:room])
    end
  end

  # Load methods which can be used for /cmd commands
  def load_command_methods()
    begin
      # Add all the newly-defined methods to our call list
      mlist = self.methods     # Get the current list of methods
      load 'user3.rb'          # install the user-defined methods
      load 'guser3.rb'         # install the GUI extensions
      begin
        load 'local.rb'        # methods local to the user
      rescue LoadError; end

      # Load in the included files' code, but only once
      unless @var[:script_lines]
        @var[:script_lines] = []
        SCRIPT_LINES__.each do |k,v|
          @var[:script_lines] += v if k.include? 'user3.rb'
        end
      end
      new_methods = self.methods.select { |m| not mlist.include? m }

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
      ####  THIS SHOULD GO IN THE NOTICE BUFFER - ADD CODE HERE  ####
      room = :current
    end
    @window.room_append(room, msg)
  end

  # Print an error to the screen
  def add_error(msg)
    add_msg "* Error: #{msg}", :notice
  end

end  # of class Chat3

client = Chat3.new
client.run
