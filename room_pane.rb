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

class RoomPane < FXPacker
  TYPE_HEIGHT   =         34    # Initial height (pixels) of the type-box
  #TEXT_COLOR    = 0xff999999
  #BACK_COLOR    = 0xff000000
  TEXT_COLOR    = 0xff000000
  BACK_COLOR    = 0xffffffff
  CURSOR_COLOR  = 0xff333333
  FONT          =  'courier'
  FONT_SIZE     =         10
  SCROLLBARS    =      false
  PAD_HISTORY   =      false
  SPLITTER_SIZE =          1

  def initialize(parent, skin = {})
    super(parent, :opts => LAYOUT_FILL)

    # We may want a 2-pixel border on the inside-top of this pane, otherwise
    # no borders.
    self.padLeft = self.padBottom = self.padRight = 0

    # Split the history display from the type-box widget
    @splitter = FXSplitter.new(self, :opts => SPLITTER_VERTICAL | LAYOUT_FILL)

    # Fully automatic resizing isn't available with splitter-contained widgets
    @splitter.connect(SEL_COMMAND) { @type_height = @type.height }

    # Splitter children
    @history = FXText.new(@splitter, :height => height - TYPE_HEIGHT - 4,
      :opts => TEXT_WORDWRAP | LAYOUT_FILL_X | TEXT_READONLY)
    @type = FXText.new(@splitter, :opts => TEXT_WORDWRAP)
    apply_skin(skin)

    # Register callbacks
    @type.connect(SEL_KEYPRESS, method(:on_keypress))
    @history.connect(SEL_FOCUSIN) { @type.setFocus() }
  end

  # Apply the appearance variables contained in our 'skin' hash, accepting
  # (and setting) default values in their absence.
  def apply_skin(skin)
    @skin = skin
    @skin[:type_height]       ||=  TYPE_HEIGHT
    @skin[:text_color]        ||=  TEXT_COLOR
    @skin[:back_color]        ||=  BACK_COLOR
    @skin[:cursor_color]      ||=  CURSOR_COLOR
    @skin[:font]              ||=  FONT
    @skin[:font_size]         ||=  FONT_SIZE
    @skin[:scrollbars]        ||=  SCROLLBARS
    @skin[:pad_history]       ||=  PAD_HISTORY
    @skin[:splitter_size]     ||=  SPLITTER_SIZE

    # Apply
    @splitter.barSize = @skin[:splitter_size]
    self.padTop = (@skin[:pad_history] ? 2 : 0)
    @type.textColor = @history.textColor = @skin[:text_color]
    @type.backColor = @history.backColor = @skin[:back_color]
    @history.cursorColor = @skin[:back_color]
    @type.cursorColor = @skin[:cursor_color]
    @type_height = @skin[:type_height]
    @history.height = @history.height + @type.height - @type_height
    font = FXFont.new(app, @skin[:font], @skin[:font_size])
    @type.font = @history.font = font
    if @skin[:scrollbars]
      @type.scrollStyle &= ~VSCROLLER_NEVER
      @history.scrollStyle &= ~VSCROLLER_NEVER
    else
      @type.scrollStyle |= VSCROLLER_NEVER
      @history.scrollStyle |= VSCROLLER_NEVER
    end
  end

  # Psuedo-automatic layout updating
  def layout
    super
    unless @type_height == @type.height
      nhh = @history.height + @type.height - @type_height
      if nhh > 0
        @history.height = nhh
        layout
      end
    end
  end

  # Set GUI focus on our type box
  def type_focus
    @type.setFocus()
  end

  # This object generates only one synthetic event - character strings
  # typed by the user.
  def on_line(&blk)
    @on_line_block = blk
  end

  # Event handler that gets called when a user presses a key inside the
  # type box
  def on_keypress(sender, selector, data)
    code = data.code
    if code == KEY_Return or code == KEY_KP_Enter
      @on_line_block.call(@type.text)
      @type.text = ''
      return true
    elsif code == KEY_Page_Up or code == KEY_Page_Down or \
          code == KEY_KP_Page_Up or code == KEY_KP_Page_Down
      @history.handle(sender, selector, data)
    end
    return false
  end

  # Some text is getting appended to our history for display
  def disp(text)
    scroll = true
    scroll = false if @history.getBottomLine < @history.text.length
    text << "\n"
    @history.appendText(text)
    @history.setBottomLine(@history.text.length) if scroll
  end

end  # of class RoomPane


###  TESTING ONLY  ###
if __FILE__ == $0
  FXApp.new do |app|
    main = FXMainWindow.new(app, "Room Pane Test", :width => 480,
                            :height => 320)
    room = RoomPane.new(main)
    room.on_line { |x| room.disp(x) }
    main.show
    app.create
    app.run
  end
end
