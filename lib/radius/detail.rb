# Radiuslib for Ruby
# Dan Debertin <airboss@nodewarrior.org>

module RADIUS
  
  # A class providing RO access to RADIUS "detail" logfiles. This is
  # the standard flat-file format used by most RADIUS servers that
  # log accounting data to regular files (i.e., not an SQL
  # database or somesuch).
  # 
  # While this class is optimized for low CPU and memory use, you
  # can expect long delays when parsing large logs
  # (hundreds of MB). 
  #
  # IMPORTANT: This class sets $/ as part of its initializer,
  # and requires that it remain set to do its work. Keep this in
  # mind when writing code that depends on the record separator.
  class Detail
    def initialize(filename)
      @filename = filename
      @file = File.open(@filename, "r")
      $/ = ''
      @pos = [0]
      @file.each { @pos << @file.pos }
      @file.rewind
      @cache = []
    end

    def inspect
      "#<RADIUS::Detail @filename=\"#@filename\", pos=#{@file.pos}, cachesize=#{@cache.nitems}>"
    end

    # Iterate through the log record by record. Each call
    # yields a Detail::Entry object.
    def each
      @file.rewind
      c = 0
      @file.each do |textrec|
	if(@cache[c])
	  yield @cache[c]
	else
	  yield @cache[c] = Entry.new(textrec)
	end
	c += 1
      end
    end

    # Access individual log entries by number, starting with 0.
    def [](idx)
      if(@cache[idx])
	@cache[idx]
      else
	return nil if(idx >= @pos.size)
	@file.pos = @pos[idx]
	@cache[idx] = Entry.new(@file.readline)
      end
    end

    # The current position in the logfile.
    def pos
      @file.pos
    end

    include Enumerable
    
    # A class representing one individual log entry.
    # Entries may be accessed in a hash-like manner.
    class Entry
      def initialize(textrec)
	@textrec = textrec
	@entry = {}
	detailparse(@textrec)
      end

      attr_reader :timestamp, :textrec

      private

      def detailparse(rec)
	rec.split(/\n/).each do |line|
	  if(line =~ /^[A-Za-z]{3}.*/)
	    @timestamp = $&
	  else
	    line.scan(/^\s*([^\s]+)\s+=\s+([^\",]?[^\s,]+[^\",]?|\"+(?:\\\"|[^\"])+\"+)(,)?$/)
	    a, v = $1, $2
	    # Remove non-escaped quotes.
	    v.gsub!(/(?:([^\\])|^)\"/, '\1')
	    @entry[a] ||= []
	    @entry[a] << v
	  end
	end
      end
      
      public

      # Is this a "Stop" accounting record?
      def stop?
	return true if(@entry['Acct-Status-Type'][0] =~ /stop/i)
	false
      end

      # Is this a "Start" accounting record?
      def start?
	return true if(@entry['Acct-Status-Type'][0] =~ /start/i)
	false
      end

      # Iterate over attribute names. Duplicates are suppressed.
      def each_attrib
	@entry.each_key { |k| yield k }
	self
      end

      # Iterate over values.
      def each_value
	@entry.each do |a|
	  a.each { |v| yield v }
	end
	self
      end

      # Iterate over each AV-pair in the entry.
      def each_pair
	@entry.each_key do |a|
	  @entry[a].each { |v| yield a, v }
	end
	self
      end

      alias each each_pair

      # Return an array of attributes present in the log entry.
      # Duplicates suppressed.
      def attributes
	attrs = []
	@entry.each_key { |k| attrs << k }
	attrs
      end

      # Return an array of values present in the log entry.
      def values
	vals = []
	@entry.each { |a| vals += a }
	vals
      end

      # Return an array of [ attr, val ] tuples.
      def to_a
	pairs = []
	@entry.each_key do |a|
	  @entry[a].each { |v| pairs << [a, v] }
	end
	pairs
      end

      # The raw record.
      def to_s
	@textrec.dup
      end

      # Return all pairs matching attr and val.
      def pairmatch(attr, val)
	pairs = []
	each_pair do |a, v|
	  pairs << [a, v] if(a == attr && v == val)
	end
	return pairs if(! pairs.empty?)
	nil
      end

      # Return all pairs for a given attribute.
      def attrmatch(attr)
	pairs = []
	each_pair do |a, v|
	  pairs << [a, v] if(a == attr)
	end
	return pairs if(! pairs.empty?)
	nil
      end

      # Like attrmatch, but return just the values.
      def index(idx)
	if(p = attrmatch(idx))
	  p.collect { |x| x[1] }
	else
	  nil
	end
      end

      def [](idx)
	index(idx)
      end

      def inspect
	"#<RADIUS::Detail::Entry id=#{self.id}>"
      end
    end
  end
end
