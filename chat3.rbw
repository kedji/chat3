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

#require 'rsa.rb'

# Ruby tool used to grab the source of included files, not just their content
SCRIPT_LINES__ = {}

RSA_BITS = 5080

# This is the dialog which pops up if you don't have a key
# (usually the first time you run chat)
class WelcomeBox < FXDialogBox
  attr_accessor :username
  def initialize(parent)
    @username = ""
    # Window decoration options
    super(parent, "Welcome to Chat 3.0", DECOR_TITLE|DECOR_BORDER|LAYOUT_FIX_WIDTH|LAYOUT_FIX_HEIGHT)
    
    # Main dialog frame
    frame = FXVerticalFrame.new(self, LAYOUT_FILL_X|LAYOUT_FILL_Y)    
    
    # Informational text
    text = "Welcome to Chat!\n\n" +
     "You must first enter a username and generate an encryption key.\n\n" +
     "Your username must comprise only letters, numbers, and underscore,\n" +
     "and be at least 3 characters long.\n\n" +
     "Generating an encryption key often takes about 30 minutes."
    infoText = FXLabel.new(frame, text, nil, LAYOUT_CENTER_X)
    
    # Username text and box
    unameText = FXLabel.new(frame, "Unique Username:", nil, LAYOUT_CENTER_X)
    unameField = FXTextField.new(frame, 20, nil, 0, TEXTFIELD_NORMAL|LAYOUT_CENTER_X|TEXTFIELD_LIMITED)
    
    # More informational text
    moreText = FXLabel.new(frame, "Click [Generate] to proceed, or [Exit] to quit.\n", nil, LAYOUT_CENTER_X)
    
    # Buttons subframe
    bFrame = FXHorizontalFrame.new(frame, LAYOUT_FILL_X)
    
    # Generate Key Button and handler
    genButton = FXButton.new(bFrame, "Generate", nil, nil, 0, BUTTON_NORMAL|LAYOUT_CENTER_X, 0, 0, 75, 20)
    genButton.connect(SEL_COMMAND) do 
      # quick test to see if the username is valid...
      if not isValid?(unameField.text)
        text = "Username may comprise only alphanumeric and underscore\nand must be longer than 2 characters."
        FXMessageBox.error(self, MBOX_OK, "Error", text)
      else # username is valid
        @username = unameField.text # needs to be accessible to calling code 
        self.handle(self, MKUINT(FXDialogBox::ID_ACCEPT, SEL_COMMAND), nil)
      end
    end
    
    # Exit Button and handler
    exitButton = FXButton.new(bFrame, "Exit", nil, nil, 0, BUTTON_NORMAL|LAYOUT_CENTER_X, 0, 0, 75, 20)
    exitButton.connect(SEL_COMMAND) do 
      self.handle(self, MKUINT(FXDialogBox::ID_CANCEL, SEL_COMMAND), nil)
    end
  end 
  
  private
  # helper function to see if username meets character requirements
  def isValid?(username)
    # allow only these characters
    valid = ("a".."z").to_a + ("A".."Z").to_a + ("0".."9").to_a + "_".to_a 
    return false if username.length < 3
    username.each_byte {|c| return false if not valid.include?(c.chr)}
    return true
  end
  
end

# This is the dialog which pops up while your key is being generated
class KeyGenBox < FXDialogBox
  def initialize(app)	
    super(app, "Generating Your Key")
    # Progress bar
    bar = FXProgressBar.new(self, nil, 0, LAYOUT_FILL_X)
    bar.total = 100
    # Text
    infoText = FXLabel.new(self, "This often takes about 30 minutes")
    # Cancel button & handler
    cancelButton = FXButton.new(self, "Cancel", nil, nil, 0, BUTTON_NORMAL|LAYOUT_CENTER_X)
    cancelButton.connect(SEL_COMMAND) do 
      Kernel.exit(0) # Allow users to quit
    end
    # Imitate Windows progressbar behavior
    app.addTimeout(250, :repeat => true) do
      bar.progress += rand(10) - bar.progress/10
    end
  end
end


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
  end

  def connect(addr, port)
    raise "You are not registered!" unless @var[:pub_rsa] and @var[:our_name]
    @connection.connect(addr, port.to_i, @var[:pub_rsa], @var[:our_name])
  end

  def run
    @fox_app.create
    dispatch(:startup)
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
            if @var[:verbose_error]
              add_error("local command '#{cmd}' generated an exception: #{$!}\n#{$@.join("\n")}")
            else
              add_error("#{$!}")
            end
          end
        else
          add_error "invalid local command: '#{cmd}'"
        end
      end
    elsif msg.length > 0
      if @connection.connected?
        dispatch :outgoing_broadcast, msg
        @connection.chat_msg(msg, @var[:room])
      else
        add_error "not connected to server"
      end
    end
  end

  # This method gets invoked if the local user's environment file (env.yml)
  # does not contain their username and public/private RSA key pair.
  def keygen_tool
    # Spawn a welcome & get username box
    welcomeBox = WelcomeBox.new(@fox_app)
    welcomeBox.create
    
    # Execute box, bail if 'Exit' is clicked
    Kernel.exit(0) if welcomeBox.execute(PLACEMENT_OWNER) == 0

    # Otherwise, "Generate Key" must have been clicked, so do that.
    waitBox = KeyGenBox.new(@fox_app)
    waitBox.create
    waitThread = Thread.new{waitBox.execute(PLACEMENT_OWNER)}
    
    # Acutally generate the RSA keypair here
    keys = Key.new
    pub_rsa, prv_rsa = Key.keygen(RSA_BITS)
    
    # Key is done; close waitBox
    waitThread.kill
    waitBox.handle(waitBox, MKUINT(FXDialogBox::ID_CANCEL, SEL_COMMAND), nil)
    
    # Notify user that their keys are done 
    FXMessageBox.information(@fox_app, MBOX_OK, "Key Generated", "You may now use Chat.") 
    return welcomeBox.username, pub_rsa, prv_rsa
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


