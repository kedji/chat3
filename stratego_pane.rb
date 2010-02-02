#!/usr/bin/env ruby

# Copyright notice:
#  (C) 2009-2010
# This software is provided 'as-is' without any express or implied warranty.
# In no event will the authors be held liable for damages arising from the
# use of this software.  All license is reserved.


# This VIEW class defines the structure of a single chat pane (FXPacker
# subclass).  The chat pane contains one history element, one type-box element,
# and a horizontal selector between them.

require 'rubygems' rescue nil
require 'fox16'
require 'fox16/colors'

include Fox

class StrategoPane < FXPacker
  FONT          =  'courier'
  FONT_SIZE     =         10
  BOARD_COLOR   = 0x00003012
  BACK_COLOR    = 0x00081010
  BLUE_COLOR    = 0x00a01010
  RED_COLOR     = 0x000000a0
  WATER_COLOR   = 0x00300000

  # Positional percentages - the board scales when resized
  BOARD_TOP     = 0.005
  BOARD_BOTTOM  = 0.90
  BOARD_LEFT    = 0.005
  BOARD_RIGHT   = 0.70

  def initialize(parent, skin = {})
    super(parent, :opts => LAYOUT_FILL)

    # We may want a 2-pixel border on the inside-top of this pane, otherwise
    # no borders.
    self.padLeft = self.padBottom = self.padRight = self.padTop = 0

    # Draw the board
    @canvas = FXCanvas.new(self, :opts => LAYOUT_FILL_X | LAYOUT_FILL_Y |
      LAYOUT_TOP | LAYOUT_LEFT)
    @canvas.connect(SEL_PAINT, method(:board_draw))
  end

  # Redraw the whole board
  def board_draw(sender, selector, event)
    FXDCWindow.new(@canvas, event) do |dc|
      dc.foreground = BACK_COLOR
      dc.fillRectangle(event.rect.x, event.rect.y, event.rect.w,
                       event.rect.h)
      dc.foreground = BOARD_COLOR
      dc.fillRectangle(*percent_rectangle(BOARD_LEFT, BOARD_TOP,
                                          BOARD_RIGHT, BOARD_BOTTOM))

      # Grab the dimensions of the board and its individual squares
      top = @canvas.height * BOARD_TOP
      bottom = @canvas.height * BOARD_BOTTOM
      left = @canvas.width * BOARD_LEFT
      right = @canvas.width * BOARD_RIGHT
      hor_i = (right - left) / 10
      ver_i = (bottom - top) / 10

      # The lakes?
      dc.foreground = WATER_COLOR
      #dc.fillCircle((hor_i * 3 + left).to_i, (ver_i * 4 + top).to_i,
      #               (hor_i * 2).to_i) #, (ver_i * 2).to_i)
      dc.fillRectangle((hor_i * 2 + left).to_i, (ver_i * 4 + top).to_i,
                       (hor_i * 2).to_i + 1, (ver_i * 2).to_i + 1)
      dc.fillRectangle((hor_i * 6 + left).to_i, (ver_i * 4 + top).to_i,
                       (hor_i * 2).to_i + 1, (ver_i * 2).to_i + 1)

      # Lines to form the 10x10 playing grid
      dc.foreground = 0x0
      11.times do |i|
        dc.drawLine(left.to_i, (i * ver_i + top).to_i,
                    right.to_i, (i * ver_i + top).to_i)
        dc.drawLine((i * hor_i + left).to_i, top.to_i,
                    (i * hor_i + left).to_i, bottom.to_i)
      end
    end
  end

  # Return the x, y, width, and height variables given (X,Y) coordinates of
  # top/left and bottom/right as percentages
  def percent_rectangle(left, top, right, bottom)
    corner = [ (@canvas.width * left).to_i,
               (@canvas.height * top).to_i ]
    corner << (@canvas.width * right).to_i - corner[0]
    corner << (@canvas.height * bottom).to_i - corner[1]
    corner
  end

  # Scale a horizontal percentage into a position on the canvas
  def xs(percent)
    (@canvas.width * percent).to_i
  end

  # Scale a vertical percentage into a position on the canvas
  def ys(percent)
    (@canvas.height * percent).to_i
  end

  # This object generates only one synthetic event - character strings
  # typed by the user.
  def on_line(&blk)
    @on_line_block = blk
  end

end  # of class StrategoPane


###  TESTING ONLY  ###
if __FILE__ == $0
  FXApp.new do |app|
    main = FXMainWindow.new(app, "Room Pane Test", :width => 480,
                            :height => 320)
    board = StrategoPane.new(main)
    board.on_line { |x| puts x }
    main.show
    app.create
    app.run
  end
end
