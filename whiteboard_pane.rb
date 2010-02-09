#!/usr/bin/env ruby

# Copyright notice:
#  (C) 2009-2010
# This software is provided 'as-is' without any express or implied warranty.
# In no event will the authors be held liable for damages arising from the
# use of this software.  All license is reserved.


require 'rubygems' rescue nil
require 'fox16'
require 'fox16/colors'

include Fox

class WhiteboardPane < FXPacker
  BOARD_WIDTH      = 480
  BOARD_HEIGHT     = 320
  BUTTON_WIDTH     = 70
  FRONT_COLOR       = 0xffffffff
  BACK_COLOR      = 0xfff0000f

  def initialize(parent, skin = {})
    super(parent, :opts => LAYOUT_FILL)
    @mouse_down = false

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
#    button_clear.connect(SEL_COMMAND) { clear_board }

    # Drawing area goes on the left
    @canvas = FXCanvas.new(frames, :opts => LAYOUT_FILL_X | LAYOUT_FILL_Y |
      LAYOUT_TOP | LAYOUT_LEFT)
    @canvas.connect(SEL_PAINT, method(:board_draw))
    @canvas.connect(SEL_LEFTBUTTONPRESS, method(:left_button_down))
    @canvas.connect(SEL_LEFTBUTTONRELEASE, method(:left_button_up))
    @canvas.connect(SEL_MOTION, method(:mouse_motion))

    # Backup of the canvas on which we're drawing
    @image = FXImage.new(app, :width => BOARD_WIDTH, :height => BOARD_HEIGHT)
    @image.create
    FXDCWindow.new(@image) do |dc|
      dc.foreground = BACK_COLOR
      dc.fillRectangle(0, 0, BOARD_WIDTH, BOARD_HEIGHT)
    end
  end

  # Redraw the whole board?  Nah, just the parts that weren't previously there.
  def board_draw(*params)
    FXDCWindow.new(@canvas) do |dc|
      dc.drawImage(@image, 0, 0)
    end
  end

  # Clear the whole board (local only)
  def clear_board
Kernel.exit
    FXDCWindow.new(@canvas) do |dc|
      dc.foreground = BACK_COLOR
      dc.fillRectangle(0, 0, @prior_width, @prior_height)
    end
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
    board_draw
  end

  # The mouse has moved.  Do something if the button is down
  def mouse_motion(sender, selector, event)
    return nil unless @mouse_down
@on_line_block.call("LN#{event.last_x},#{event.last_y},#{event.win_x},#{event.win_y}")
#    FXDCWindow.new(@canvas, event) do |dc|
    FXDCWindow.new(@image, event) do |dc|
      dc.foreground = FRONT_COLOR
      dc.drawLine(event.last_x, event.last_y, event.win_x, event.win_y)
      dc.drawLine(10, 10, event.win_x, event.win_y)
    end
    true
  end

end  # of class WhiteboardPane


#### Do not include below this line - TESTING ONLY ####
if __FILE__ == $0
  FXApp.new do |app|
    main = FXMainWindow.new(app, "Whiteboard Test",
      :width => WhiteboardPane::BOARD_WIDTH,
      :height => WhiteboardPane::BOARD_HEIGHT)
    board = WhiteboardPane.new(main)
    board.on_line { |x| puts x }
    main.show
    app.create
    app.run
  end
end
