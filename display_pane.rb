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

class DisplayPane < FXPacker
  BOARD_WIDTH      = 480
  BOARD_HEIGHT     = 320 
  BUTTON_WIDTH     = 70
  FONT             = 'courier'
  FONT_SIZE        = 8
  
  # These are our default skin values
  DEFAULTS = {
    :window_height    => 320,
    :window_width     => 480,
    :show_tabs        => true,
    :window_title     => 'Chat 3.0',
    :font             => 'monospace',
    :font_size        => 7,
    :back_color       => 0xffffffff,
    :text_color       => 0xff000000,
    :cursor_color     => 0xff333333,
    :scrollbars       => false,
    :pad_history      => false,
    :splitter_size    => 1,
    :type_height      => 34,
  }

  def initialize(parent, skin)
    super(parent, :opts => LAYOUT_FILL)

    # We may want a 2-pixel border on the inside-top of this pane, otherwise
    # no borders.
    self.padLeft = self.padBottom = self.padRight = self.padTop = 0

    # Draw the top-level board
    frames = FXPacker.new(self, :opts => LAYOUT_FILL)

    # Buttons go on the right
    button_list = FXPacker.new(frames, :opts => LAYOUT_FILL_Y |
      LAYOUT_SIDE_RIGHT | LAYOUT_FIX_WIDTH, :width => BUTTON_WIDTH)
    button_post = FXButton.new(button_list, "Post", :opts => FRAME_RAISED |
      FRAME_THICK | LAYOUT_FILL_X | LAYOUT_SIDE_TOP)
    button_post.connect(SEL_COMMAND) { }

    # Exit button at the bottom all by itself
    button_bye = FXButton.new(button_list, "Close", :opts => FRAME_RAISED |
      FRAME_THICK | LAYOUT_FILL_X | LAYOUT_SIDE_BOTTOM)
    button_bye.connect(SEL_COMMAND) { @on_line_block.call('/close') }

    # Table goes on the left
    cframe = FXHorizontalFrame.new(frames, :opts => LAYOUT_FILL | FRAME_SUNKEN |
      FRAME_THICK | LAYOUT_SIDE_LEFT, :padLeft => 0, :padRight => 0,
      :padTop => 0, :padBottom => 0, :hSpacing => 0, :vSpacing => 0)
    @table = FXTable.new(cframe, :opts => LAYOUT_FILL_Y | LAYOUT_FILL_X |
      TABLE_COL_SIZABLE)
    @table.font = FXFont.new(app, FONT, FONT_SIZE)
    @table.visibleRows = 20
    @table.visibleColumns = 2
    @table.setBackColor(FXRGB(255, 255, 255))
    @table.setCellColor(0, 0, FXRGB(225, 255, 225))
    @table.setCellColor(1, 0, FXRGB(225, 225, 255))
    @table.setCellColor(0, 1, FXRGB(225, 255, 225))
    @table.setCellColor(1, 1, FXRGB(225, 225, 255))
    @table.setTableSize(skin.length, 2)
    @table.rowHeaderWidth = 110
  end

  # Make sure all the skin options are set.  Any absent items will get
  # set to their default values.
  def self.merge_defaults(skin)
    DEFAULTS.each do |k,v|
      skin[k] = v if skin[k].nil?
    end
  end

  # This object generates only one synthetic event - character strings
  # "typed" by the user.
  def on_line(&blk)
    @on_line_block = blk
  end

  # We've gotten a list of drawing commands from the room.  Let's draw them!
  def disp(text)
  end

end  # of class DisplayPane


#### Do not include below this line - TESTING ONLY ####
if __FILE__ == $0
  FXApp.new do |app|
    main = FXMainWindow.new(app, "Display Test",
      :width => DisplayPane::BOARD_WIDTH,
      :height => DisplayPane::BOARD_HEIGHT)
    board = DisplayPane.new(main)
    board.on_line { |x| board.disp(x) ; puts x }
    main.show
    app.create
    app.run
  end
end
