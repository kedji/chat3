#!/usr/bin/env ruby

# Copyright notice:
#  (C) 2009-2010
# This software is provided 'as-is' without any express or implied warranty.
# In no event will the authors be held liable for damages arising from the
# use of this software.  All license is reserved.

####  Whiteboard Protocol  ####
# Whiteboard messages are a space-delimited set of commands.  Commands are
# made up of a type-byte and then a comma-delimited set of values.  As an
# example, here's a message containing two line commands:
# "L10,20,15,25 L15,20,10,25"
# The 'L' character specifies that each command is a line, and the LINE
# command takes four integer values - x1,y1,x2,y2.

require 'rubygems' rescue nil
require 'fox16'
require 'fox16/colors'

include Fox

class WhiteboardPane < FXPacker
  BOARD_WIDTH      = 480     # Initial window width
  BOARD_HEIGHT     = 320     # Initial window height
  IMG_WIDTH        = 1920    # Maximum width of our canvas
  IMG_HEIGHT       = 1080    # Maximum height of our canvas
  BUTTON_WIDTH     = 70
  BACK_COLOR       = 0xffffffff
  FRONT_COLOR      = 0xfff0000f
  BUFFER_TIME      = 1.1     # Seconds for which we buffer

  def initialize(parent, skin = {})
    super(parent, :opts => LAYOUT_FILL)
    @mouse_down = false
    @cmds = []
    @cmd_time = nil
    @colors = { 'R' => 0xff0000ff,
                'B' => 0xfff0000f,
                'G' => 0xff00aa00,
                'D' => 0xff000000 }
    @color = 'D'

    # We may want a 2-pixel border on the inside-top of this pane, otherwise
    # no borders.
    self.padLeft = self.padBottom = self.padRight = self.padTop = 0

    # Draw the top-level board
    frames = FXPacker.new(self, :opts => LAYOUT_FILL)

    # Buttons go on the right
    button_list = FXPacker.new(frames, :opts => LAYOUT_FILL_Y |
      LAYOUT_SIDE_RIGHT | LAYOUT_FIX_WIDTH, :width => BUTTON_WIDTH)
    button_clear = FXButton.new(button_list, "Clear", :opts => FRAME_RAISED |
      FRAME_THICK | LAYOUT_FILL_X | LAYOUT_SIDE_TOP)
    button_clear.connect(SEL_COMMAND) { clear_board }

    # Now draw the color buttons
    @colors.each do |c,v|
      button = FXButton.new(button_list, " ", :opts => FRAME_RAISED |
        FRAME_THICK | LAYOUT_FILL_X | LAYOUT_SIDE_TOP)
      button.connect(SEL_COMMAND) { @color = c }
      button.backColor = v
    end

    # Drawing area goes on the left
    cframe = FXHorizontalFrame.new(frames, :opts => LAYOUT_FILL | FRAME_SUNKEN |
      FRAME_THICK | LAYOUT_SIDE_LEFT, :padLeft => 0, :padRight => 0,
      :padTop => 0, :padBottom => 0, :hSpacing => 0, :vSpacing => 0)
    @canvas = FXCanvas.new(cframe, :opts => LAYOUT_FILL)
    @canvas.connect(SEL_PAINT, method(:board_draw))
    @canvas.connect(SEL_LEFTBUTTONPRESS, method(:left_button_down))
    @canvas.connect(SEL_LEFTBUTTONRELEASE, method(:left_button_up))
    @canvas.connect(SEL_MOTION, method(:mouse_motion))

    # Backup of the canvas on which we're drawing
    @image = FXImage.new(app, :width => 1920, :height => 1080)
    @image.create
    FXDCWindow.new(@image) do |dc|
      dc.foreground = BACK_COLOR
      dc.fillRectangle(0, 0, 1920, 1080)
    end
  end

  # Redraw the whole board?  Restore an image?
  def board_draw(*params)
    FXDCWindow.new(@canvas) do |dc|
      dc.drawImage(@image, 0, 0)
    end
  end

  # Clear the whole board (local only)
  def clear_board
    FXDCWindow.new(@image) do |dc|
      dc.foreground = BACK_COLOR
      dc.fillRectangle(0, 0, IMG_WIDTH, IMG_HEIGHT)
    end
    board_draw
  end

  # This object generates only one synthetic event - character strings
  # "typed" by the user.
  def on_line(&blk)
    @on_line_block = blk
  end

  # The left mouse button has been pressed
  def left_button_down(sender, selector, event)
    @canvas.grab
    @mouse_down = true
  end

  # The left mouse button has been released
  def left_button_up(sender, selector, event)
    @canvas.ungrab
    @mouse_down = false
    flush_commands
    board_draw
  end

  # The mouse has moved.  Do something if the button is down
  def mouse_motion(sender, selector, event)
    return nil unless @mouse_down

    # Draw the temporary line just for immediate user feedback
    FXDCWindow.new(@canvas) do |dc|
      dc.foreground = @colors[@color]
      dc.drawLine(event.last_x, event.last_y, event.win_x, event.win_y)
    end

    # Draw the permanent line to our buffer
    FXDCWindow.new(@image) do |dc|
      dc.foreground = @colors[@color]
      dc.drawLine(event.last_x, event.last_y, event.win_x, event.win_y)
    end

    # Now send the line to the room
    buffer_command("L,#{@color},#{event.last_x},#{event.last_y}" +
                   ",#{event.win_x},#{event.win_y}")
    true
  end

  # Buffer commands so we can send them in chunks
  def buffer_command(cmd)
    @cmd_time ||= Time.now.to_f
    @cmds << cmd
    flush_commands if Time.now.to_f - @cmd_time > BUFFER_TIME
  end

  # Send all the buffered commands, if any
  def flush_commands
    @cmd_time = nil
    @on_line_block.call(@cmds.join(' ')) unless @cmds.empty?
    @cmds = []
  end

  # We've gotten a list of drawing commands from the room.  Let's draw them!
  def disp(text)
    FXDCWindow.new(@image) do |dc|
      text.split(' ').each do |cmd|
        cmd = cmd.split(',')
        if cmd.first == 'L'
          dc.foreground = @colors[cmd[1]].to_i
          dc.drawLine(cmd[2].to_i, cmd[3].to_i + 1, cmd[4].to_i, cmd[5].to_i + 1)
        end
      end
    end
    board_draw
  end

end  # of class WhiteboardPane


#### Do not include below this line - TESTING ONLY ####
if __FILE__ == $0
  FXApp.new do |app|
    main = FXMainWindow.new(app, "Whiteboard Test",
      :width => WhiteboardPane::BOARD_WIDTH,
      :height => WhiteboardPane::BOARD_HEIGHT)
    board = WhiteboardPane.new(main)
    board.on_line { |x| board.disp(x) ; puts x }
    main.show
    app.create
    app.run
  end
end
