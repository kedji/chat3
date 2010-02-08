#!/usr/bin/env ruby

# This little script is designed to help all those little computer newbies
# out there more simply run Ruby programs.  Namely, it takes a collection
# of .rb files which have been kept separate for development purposes and
# aggregates them into one large file.  This way they only have to keep track
# of one file.  The approach here is VERY naive - it just recursively
# replaces calls to require() with the content of that file.

# Note, to preclude certain lines from being put into the final aggregated
# file, put those lines to be excluded below this comment line:

#### Do not include ####

# Nothing below that line will get added to the final product.  This tool does
# NOT replace load() calls.


if ARGV.empty?
  puts "Usage: #{$0} <entry-file> [post-file...]"
  Kernel.exit(1)
end

program = []
ARGV.each { |f| program += File.readlines(f) }
pos = 0
files = {}
while pos < program.length
  line = program[pos]
  if (line =~ /require '/) == 0 and line =~ /.rb'/
    file = line.split("'")[1]
    if not files[file]
      files[file] = true
      contents = File.readlines(file)
      spos = contents.find_index { |x| x.index('#### Do') == 0 }
      contents[spos..-1] = [] if spos
      contents.unshift "#### Aggregator included '#{file}' ####"
      contents.push    "#### End of aggregated '#{file}' ####"
      program[pos, 1] = contents
    end
  end
  pos += 1
end

program.each { |x| puts x }
