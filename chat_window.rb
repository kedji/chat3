#!/usr/bin/env ruby

# Copyright notice:
#  (C) 2009-2010
# This software is provided 'as-is' without any express or implied warranty.
# In no event will the authors be held liable for damages arising from the
# use of this software.  All license is reserved.


# This class defines the structure of the main chat window.  When it closes,
# the program exits.  It contains one or more room_pane widgets inside of
# a switcher which may be controlled by visible tabs.

require 'rubygems' rescue nil
require 'fox16'
require 'fox16/colors'
require 'room_pane.rb'
require 'whiteboard_pane.rb'

include Fox


# Helper font-selection dialog box
class FontDialogBox < FXDialogBox
  def initialize(parent, opts_array)
    super(parent, "Choose a font", DECOR_TITLE | DECOR_BORDER)
    @fs = FXFontSelector.new(self)
    @fs.fontSelection.face = opts_array[0] if opts_array[0]
    @fs.fontSelection.size = opts_array[1].to_i * 10 if opts_array[1]
    @fs.acceptButton.connect(SEL_COMMAND) do
      opts_array[0] = @fs.fontSelection.face.dup
      opts_array[1] = @fs.fontSelection.size.to_i / 10
      self.handle(self, MKUINT(FXDialogBox::ID_ACCEPT, SEL_COMMAND), nil)
    end
    @fs.cancelButton.connect(SEL_COMMAND) do
      self.handle(self, MKUINT(FXDialogBox::ID_CANCEL, SEL_COMMAND), nil)
    end
  end
end

# Helper color-selection dialog box
class ColorDialogBox < FXDialogBox
  def initialize(parent, opts_array)
    super(parent, "Choose a #{opts_array[0]} color", DECOR_TITLE | DECOR_BORDER)
    @fs = FXColorSelector.new(self)
    @fs.acceptButton.connect(SEL_COMMAND) do
      opts_array[1] = @fs.rgba
      self.handle(self, MKUINT(FXDialogBox::ID_ACCEPT, SEL_COMMAND), nil)
    end
    @fs.cancelButton.connect(SEL_COMMAND) do
      self.handle(self, MKUINT(FXDialogBox::ID_CANCEL, SEL_COMMAND), nil)
    end
  end
end


#####   MAIN CHAT WINDOW CLASS - This is the top of the GUI   #####
class ChatWindow < FXMainWindow
  include Responder
  ID_NEXT_TAB   = ID_LAST + 1
  ID_PREV_TAB   = ID_NEXT_TAB + 1

  # These are our default skin values
  DEFAULTS = {
    :window_height    => 320,
    :window_width     => 480,
    :show_tabs        => true,
    :window_title     => 'Chat 3.0',
    :font             => 'Monospace',
    :font_size        => 7,
    :back_color       => 0xffffffff,
    :text_color       => 0xff000000,
    :cursor_color     => 0xff333333,
    :scrollbars       => false,
    :pad_history      => false,
    :splitter_size    => 1,
    :type_height      => 34,
  }

  def initialize(app, skin)
    @skin = skin
    @empties = []
    @waiting_tabs = {}
    merge_defaults(@skin)

    # Create the main window
    super(app, @skin[:window_title], :width => @skin[:window_width],
                                     :height => @skin[:window_height])
    
    # Top level container for the tab bar and the switcher.  We don't let
    # the tab system actually manage anything, because we want to be able
    # to turn tabs on and off.  So we have a tab bar with no content that
    # drives a switcher (or just a switcher, if so chosen).
    packer = FXPacker.new(self, :opts => LAYOUT_FILL)
    packer.padTop = packer.padBottom = packer.padLeft = packer.padRight = 0
    packer.vSpacing = 0

    # Tab bar and its empty content
    @tabs = FXTabBook.new(packer, :opts => LAYOUT_FILL_X | LAYOUT_SIDE_TOP)
    @tabs.padBottom = @tabs.padTop = @tabs.padLeft = @tabs.padRight = 0
    @tab_names = [ FXTabItem.new(@tabs, "chat", nil) ]
    empty = FXPacker.new(@tabs)
    empty.padBottom = empty.padTop = empty.padLeft = empty.padRight = 0
    @empties << empty

    # The top level switcher.  Each switchable instance is a RoomPane instance
    @switcher = FXSwitcher.new(packer, :opts => LAYOUT_FILL)
    @switcher.padBottom = @switcher.padTop = 0
    @switcher.padLeft = @switcher.padRight = 0
    @channels = [ [ 'chat', RoomPane.new(@switcher, skin) ] ]
    @channels.first.last.type_focus rescue nil

    # Tabs are always off when there's only one room to display
    @tabs.hide

    # Tab selection should map directly to the switcher
    @tabs.connect(SEL_COMMAND, method(:on_tab_select))

    # Hook up keyboard accelerators old-school FXRuby style
    FXMAPFUNC(SEL_COMMAND, ID_NEXT_TAB, :next_tab)
    accelTable.addAccel(fxparseAccel("Ctrl+N"),
                        self, FXSEL(SEL_COMMAND, ID_NEXT_TAB))
    accelTable.addAccel(Fox.MKUINT(KEY_Tab, CONTROLMASK),
                        self, FXSEL(SEL_COMMAND, ID_NEXT_TAB))
    accelTable.addAccel(Fox.MKUINT(KEY_KP_Tab, CONTROLMASK),
                        self, FXSEL(SEL_COMMAND, ID_PREV_TAB))
    FXMAPFUNC(SEL_COMMAND, ID_PREV_TAB, :prev_tab)
    accelTable.addAccel(fxparseAccel("Ctrl+Shift+N"),
                        self, FXSEL(SEL_COMMAND, ID_PREV_TAB))
    accelTable.addAccel(Fox.MKUINT(KEY_Tab, CONTROLMASK | SHIFTMASK),
                        self, FXSEL(SEL_COMMAND, ID_PREV_TAB))
    accelTable.addAccel(Fox.MKUINT(KEY_KP_Tab, CONTROLMASK | SHIFTMASK),
                        self, FXSEL(SEL_COMMAND, ID_PREV_TAB))
    accelTable.addAccel(Fox.MKUINT(KEY_ISO_Left_Tab, CONTROLMASK | SHIFTMASK),
                        self, FXSEL(SEL_COMMAND, ID_PREV_TAB))
  end

  def create
    super
    show(PLACEMENT_SCREEN)
  end

  # Make sure all the skin options are set.  Any absent items will get
  # set to their default values.
  def merge_defaults(skin)
    DEFAULTS.each do |k,v|
      skin[k] = v if skin[k].nil?
    end
  end

  # Turn activity notification on or off for the given tab index
  def tab_notify(indx, notify)
    notify = false if indx == @tabs.current
    prior = @waiting_tabs[indx]
    @waiting_tabs[indx] = notify
    return nil unless prior ^ notify   # leave if status isn't changing
    if notify
      @tab_names[indx].text = @tab_names[indx].text + '+'
    else
      @tab_names[indx].text = @tab_names[indx].text[0...-1]
    end
  end

  def select_tab(indx)
    @tabs.current = indx
    tab_notify(indx, false)
    @switcher.current = indx
    @on_room_block.call(@channels[indx].first)
    @channels[indx].last.type_focus rescue nil
  end
  
  # A user has clicked on a tab
  def on_tab_select(sender, selector, e)
    select_tab(@tabs.current)
  end

  # Register a callback block for handling user-typed lines in one of the
  # RoomPane widgets.
  def on_line(&blk)
    @on_line_block = blk
    @channels.each { |name,pane| pane.on_line(&blk) }
  end

  # Register a callback for when the user selects a different room (or
  # private message context) using the GUI tabs.
  def on_room_change(&blk)
    @on_room_block = blk
  end

  # Add text to the provided room (or private message context)
  # A room name of :current means send to the current room, whatever it is.
  # A room name of :global means send it to all rooms.
  def room_append(room_name, text)
    room_name = @channels[@switcher.current].first if room_name == :current

    # Find the room (or rooms) to which we should send this message
    channel = @channels.select do |name,pane|
      room_name == name or room_name == :global
    end

    # Do we need to unhide a room?
    if channel.length == 1 and room_name.class == String
      indx = @channels.index(channel.first)
      unless indx == 0
        @tab_names[indx].show
        (@tabs.create ; @tabs.show) if @skin[:show_tabs]
      end
    end

    # Do we need to create a room?  I think we might!
    if channel.empty? and room_name.class == String
      new_tab(room_name)
      channel = [ @channels.last ]
    end
    channel.each do |chan|
      indx = @channels.index(chan)
      chan.last.disp(text)
      tab_notify(indx, true) unless room_name == :global
    end
  end

  # Adding a new tab and switcher element.  Optionally you can specify a
  # class (a pane type) which will be spawned.  RoomPane is spawned by default.
  # Checks for duplicates automatically.
  def new_tab(name, klass = RoomPane)
    # Don't do anything if we already have this tab
    @channels.each { |cname,_| return nil if cname == name }

    # Add the visual indication of this tab
    @tab_names << FXTabItem.new(@tabs, name, nil)
    empty = FXPacker.new(@tabs)
    empty.padBottom = empty.padTop = empty.padLeft = empty.padRight = 0
    @empties << empty

    # Create the content of this channel - probably a RoomPane
    new_channel = klass.new(@switcher, @skin)
    @channels << [ name, new_channel ]
    new_channel.create
    new_channel.on_line(&@on_line_block)   # register our callback function

    # Show the tabs (if so desired) now that we know we have more than one.
    (@tabs.create ; @tabs.show) if @skin[:show_tabs]
  end

  # Remove the named tab and hide its corresponding switcher element
  def remove_tab(name)
    indx = @channels.index(@channels.find { |room,_| room == name }).to_i
    return nil unless indx > 0

    # Update this particular tab name and our switcher context
    @tab_names[indx].hide
    @tabs.current = 0
    @switcher.current = 0
    
    # Now update the tab bar as a whole and redraw
    if visible_tabs < 2
      @tabs.hide
    end
    @tabs.recalc
    @on_room_block.call(@channels[0].first)
  end

  def next_tab(sender, sel, data)
    max = @tab_names.length
    indx = (@tabs.current + 1) % max
    until @tab_names[indx].visible?
      indx = (indx + 1) % max
    end
    select_tab(indx)
  end

  def prev_tab(sender, sel, data)
    max = @tab_names.length
    indx = (@tabs.current - 1) % max
    until @tab_names[indx].visible?
      indx = (indx - 1) % max
    end
    select_tab(indx)
  end
  
  # The sneaky user has changed the room without the GUI.  Bastards!
  def room_change(room_name)
    indx = @channels.index(@channels.find { |room,_| room == room_name })
    unless indx
      indx = @channels.length
      new_tab(room_name)
    end
    @tabs.current = indx
    @switcher.current = indx
    @tab_names[indx].show
    (@tabs.create ; @tabs.show) if @skin[:show_tabs] and indx != 0
    tab_notify(indx, false)
    @tabs.recalc
    @channels[indx].last.type_focus rescue nil
  end

  # Return the number of visible (unhidden) tabs
  def visible_tabs
    count = 0
    @tab_names.each { |x| count += 1 if x.visible? }
    count
  end

  # Apply the new skin (or the old one) to all the panes that'll take it.
  def apply_skin(skin = nil)
    skin ||= @skin
    @skin = skin
    @channels.each do |_,pane|
      pane.apply_skin(@skin) rescue nil
    end
  end

end  # of class ChatWindow

#### Do not include below this line - TESTING ONLY ####
if __FILE__ == $0
  FXApp.new do |app|
    ChatWindow.new(app)
    app.create
    app.run
  end
end
