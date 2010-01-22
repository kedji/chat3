#!/usr/bin/env ruby

# Copyright notice:
#  (C) 2009-2010
# This software is provided 'as-is' without any express or implied warranty.
# In no event will the authors be held liable for damages arising from the
# use of this software.  All license is reserved.


# This class defines the structure of the main chat window.  When it closes,
# the program exits.  It contains one or more room_pane widgets inside of
# a switcher which may be controlled by visible tabs.

require 'rubygems'
require 'fox16'
require 'fox16/colors'
require 'room_pane.rb'

include Fox

class ChatWindow < FXMainWindow
  WINDOW_HEIGHT = 320
  WINDOW_WIDTH  = 480
  WINDOW_TITLE  = "Chat 3.0"
  SHOW_TABS     = true

  def initialize(app, skin = {})
    @skin = skin
    @empties = []
    @waiting_tabs = {}

    # Set up some default appearance values first
    @skin[:window_height]    ||=  WINDOW_HEIGHT
    @skin[:window_width]     ||=  WINDOW_WIDTH
    @skin[:window_title]     ||=  WINDOW_TITLE
    @skin[:show_tabs]        ||=  SHOW_TABS

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
    @channels.first.last.type_focus

    # Tabs are always off when there's only one room to display
    @tabs.hide

    # Tab selection should map directly to the switcher
    @tabs.connect(SEL_COMMAND, method(:on_tab_select))
  end

  def create
    super
    show(PLACEMENT_SCREEN)
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

  # A user has clicked on a tab
  def on_tab_select(sender, selector, e)
    indx = @tabs.current
    tab_notify(indx, false)
    @switcher.current = indx
    @on_room_block.call(@channels[indx].first)
    @channels[indx].last.type_focus
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

  # Adding a new tab and switcher element
  def new_tab(name)
    @tab_names << FXTabItem.new(@tabs, name, nil)
    empty = FXPacker.new(@tabs)
    empty.padBottom = empty.padTop = empty.padLeft = empty.padRight = 0
    @empties << empty
    new_channel = RoomPane.new(@switcher, @skin)
    @channels << [ name, new_channel ]
    new_channel.create
    new_channel.on_line(&@on_line_block)
    (@tabs.create ; @tabs.show) if @skin[:show_tabs]
  end

  # Remove the named tab and its corresponding switcher element
  def remove_tab(name)
    indx = @channels.index(@channels.find { |room,_| room == name }).to_i
    return nil unless indx > 0
    @tab_names[indx].hide
    @tabs.current = 0
    @switcher.current = 0
    @tabs.recalc
    @on_room_block.call(@channels[0].first)
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
    tab_notify(indx, false)
    @tabs.recalc
    @channels[indx].last.type_focus
  end

end  # of class ChatWindow


if __FILE__ == $0
  FXApp.new do |app|
    ChatWindow.new(app)
    app.create
    app.run
  end
end
