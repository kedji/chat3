#!/usr/bin/env ruby

# Copyright notice:
#  (C) 2009-2010
# This software is provided 'as-is' without any express or implied warranty.
# In no event will the authors be held liable for damages arising from the
# use of this software.  All license is reserved.


# The View and Controller for Stratego within Chat 3.0.  Fixed aspect-ratio,
# scalable board.

require 'rubygems' rescue nil
require 'fox16'
require 'fox16/colors'

include Fox

class StrategoPane < FXPacker
  BOARD_WIDTH      = 480
  BOARD_HEIGHT     = 320
  ASPECT           = BOARD_WIDTH.to_f / BOARD_HEIGHT.to_f
  FONT             = 'helvetica'
  FONT_SIZE        =         10
  BOARD_COLOR      = 0x00003012
  BACK_COLOR       = 0x00081010
  BLUE_COLOR       = 0x00a01010
  RED_COLOR        = 0x000000a0
  WATER_COLOR      = 0x00300000
  HIGHLIGHT_COLOR  = 0x0000bbbb

  # Positional percentages - the board scales when resized.  These are
  # percentages of the HEIGHT of the window.  That is, width values can
  # be (and will be) more than 100%.
  BOARD_TOP     = 0.005
  BOARD_BOTTOM  = 0.905
  BOARD_LEFT    = 0.005
  BOARD_RIGHT   = 0.905
  SQUARE_INC    = (BOARD_BOTTOM - BOARD_TOP) / 10

  def initialize(parent, skin = {})
    super(parent, :opts => LAYOUT_FILL)

    # We may want a 2-pixel border on the inside-top of this pane, otherwise
    # no borders.
    self.padLeft = self.padBottom = self.padRight = self.padTop = 0

    # Draw the board
    @canvas = FXCanvas.new(self, :opts => LAYOUT_FILL_X | LAYOUT_FILL_Y |
      LAYOUT_TOP | LAYOUT_LEFT)
    @canvas.connect(SEL_PAINT, method(:board_draw))
    @canvas.connect(SEL_LEFTBUTTONPRESS, method(:left_button_down))
  end

  # Redraw the whole board
  def board_draw(sender, selector, event)
    FXDCWindow.new(@canvas, event) do |dc|
      dc.foreground = BACK_COLOR
      dc.fillRectangle(event.rect.x, event.rect.y, event.rect.w,
                       event.rect.h)

      # Grab the dimensions of the board and its individual squares
      @inc = (@canvas.height * SQUARE_INC).to_i
      @top = (@canvas.height * BOARD_TOP).to_i
      @bottom = @top + @inc * 10
      @left = (@canvas.height * BOARD_LEFT).to_i
      @right = @top + @inc * 10

      # The background
      dc.foreground = BOARD_COLOR
      dc.fillRectangle(@left, @top, @inc * 10, @inc * 10)

      # The lakes?
      dc.foreground = WATER_COLOR
      dc.fillRectangle(@inc * 2 + @left,  @inc * 4 + @top,
                       @inc * 2 + 1,      @inc * 2 + 1)
      dc.fillRectangle(@inc * 6 + @left,  @inc * 4 + @top,
                       @inc * 2 + 1,      @inc * 2 + 1)

      # Lines to form the 10x10 playing grid
      dc.foreground = 0x0
      11.times do |i|
        dc.drawLine(@left,             i * @inc + @top,
                    @right,            i * @inc + @top)
        dc.drawLine(i * @inc + @left,  @top,
                    i * @inc + @left,  @bottom)
      end
    end
  end

  # This object generates only one synthetic event - character strings
  # "typed" by the user.
  def on_line(&blk)
    @on_line_block = blk
  end

  # Highlight (or un-highlight) the given square
  def highlight(x, y)
    FXDCWindow.new(@canvas) do |dc|
      dc.foreground = HIGHLIGHT_COLOR
      dc.drawRectangle(@left + @inc * x + 1, @top + @inc * y + 1,
                       @inc - 2, @inc - 2)
    end    
  end

  # The left mouse button has been pressed
  def left_button_down(sender, selector, event)
    x = (event.win_x - @left) / @inc
    y = (event.win_y - @top) / @inc
    #	highlight(x, y)
    draw_piece(x, y, "B", [:red, :blue][(x+y) % 2])
  end

  # Draw a piece with the given name/color at the given location
  def draw_piece(x, y, name, color)
    FXDCWindow.new(@canvas) do |dc|
      dc.foreground = (color == :red ? RED_COLOR : BLUE_COLOR)
      dc.fillRectangle(@left + @inc * x + 4, @top + @inc * y + 3,
                       @inc - 7, @inc - 5)
      dc.foreground = 0
      dc.drawRectangle(@left + @inc * x + 4, @top + @inc * y + 3,
                       @inc - 8, @inc - 6)

## ???  How does one write text to the screen?
#myf = FXFont.new(app, FONT, FONT_SIZE)
#dc.font = myf
#dc.drawText(@left + @inc * x + 6, @top + @inc * y + 3, name)
    end
  end

  ## ???  Clipping?  I don't know.
  def img_piece(color, name)
    img = FXImage.new(app, :width => @inc - 8, :height => @inc - 8)
    img.create
    FXDCWindow.new(img) do |dc|
      dc.foreground = (color == :red ? RED_COLOR : BLUE_COLOR)
      dc.fillRectangle(0, 0, img.width, img.height)
    end
    img
  end

end  # of class StrategoPane


#### Do not include below this line - TESTING ONLY ####
if __FILE__ == $0
  FXApp.new do |app|
    main = FXMainWindow.new(app, "Stratego Test",
      :width => StrategoPane::BOARD_WIDTH, :height => StrategoPane::BOARD_HEIGHT)
    board = StrategoPane.new(main)
    board.on_line { |x| puts x }
    main.show
    app.create
    app.run
  end
end
