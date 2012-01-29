# Radiuslib for Ruby
# Dan Debertin <airboss@nodewarrior.org>


require "radius/radiusutil"

module RADIUS 

  # RADIUS::Dictionary. Provides a parser and read-only access to a RADIUS dictionary.
  # Note that dictionary syntax is not standardized anywhere; it rests only on 
  # convention. I have used the extensive dictionaries packaged with the 
  # FreeRADIUS project for testing; this implementation supports all syntaxes 
  # contained in those dictionaries with the exception of dictionary.tunnel --
  # tagged attributes are not supported in this release at all -- and the
  # 'octets' datatype, which is treated as an opaque string. Both of these
  # should be supported in the next release.
  #
  class Dictionary
    # Parses the file given as its argument. Will automatically recurse any
    # $INCLUDE directives it finds in that file, though it will throw
    # exceptions if duplicate inclusion is detected.
    #
    # The *MultiHash* and *InvHash* mixins are documented in <em>radiusutil.rb</em>.
    def initialize(dictfile="/etc/raddb/dictionary")
      @dictfile = dictfile
      @dictpath = /^.*\//.match(@dictfile).to_s
      @files = []
      @attribs = [].extend(MultiHash)
      @values = {}
      @vendors = {}.extend(InvHash)
      @vsa = [].extend(MultiHash)
      @set_vendor = nil
      @be_vendor = nil
      @vsa_name_lookup = {}
      file = file_init(@dictfile)
      parse(file)
      file.close
      clean
    end

    private

    # Open a file after verifying that a file with its inode hasn't already
    # been opened.
    def file_init(fn)
      if(@be_vendor)
        @be_vendor = nil
  # raise RadiusUtilError, "EOF with open BEGIN/END-VENDOR block"
      end
      begin
	ino = File.stat(fn).ino
	rescue
	if(fn !~ /#{@dictpath}/)
	  fn = @dictpath + fn
	  retry
	else
	  raise
	end
      end
      if(@files.detect { |f| f == ino })
	raise RadiusUtilError, "File already included, refusing to recurse infinitely: #{fn}"
      end
      @files << ino
      File.open(fn, "r")
    end

    # Parse the dictionary at the File object <em>file</em>.
    def parse(file)
      file.each do |line|
	line.chomp!
	line.sub!(/#.*$/, "")
	case line
	when /^($|#|\s+)/
	  next
  when /^ATTRIBUTE\s+([-_A-Za-z0-9\.]+)\s+(\w+)\s+([\w\-  ]+)\s*($|[-A-Za-z0-9]+)\s*$/
	  begin
	    storeattrib([$1, $2, $3, $4])
	    rescue
	    raise "#{file.path}(#{file.lineno}): #{$!}"
	  end
  # try to support loading dictionary files from FreeRADIUS
  # ATTRIBUTE	Password				2	string	encrypt=1
  # ATTRIBUTE Tunnel-Password       69  string  has_tag,encrypt=2
  # ATTRIBUTE Tunnel-Medium-Type      65  integer has_tag  
  when /^ATTRIBUTE\s+([-_A-Za-z0-9]+)\s+(\w+)\s+(\w+)\s+[a-z,_=0-9]+\s*$/
	  begin
	    storeattrib([$1, $2, $3])
	    rescue
	    raise "#{file.path}(#{file.lineno}): #{$!}"
	  end
	when /^ATTRIB_NMC\s+([-_A-Za-z0-9]+)\s+((?:0x)?[0-9A-Fa-f]+)\s+(\w+)\s*$/
	  # Stupid USR...
	  begin
	    if(! @vendors['USR'])
	      storevendor(['USR', 429])
	    end
	    storeattrib([$1, sprintf("%d", $2), $3, 'USR'])
	    rescue
	    raise "#{file.path}(#{file.lineno}): #{$!}"
	  end
	when /^VALUE\s+([-_A-Za-z0-9]+)\s+([-A-Za-z0-9\._\/+,]+)\s+((0x)?[0-9a-fA-F]+)\s*$/
	  begin
	    storeval([$1, $2, $3])
	    rescue
	    raise "#{file.path}(#{file.lineno}): #{$!}"
	  end
	when /^\$INCLUDE\s+([^\s]+)\s*$/
	  parse(file_init($1))
	when /^VENDOR\s+([-A-Za-z0-9]+)\s+(\w+)\s*$/
	  begin
	    storevendor([$1, $2])
	    rescue
	    raise "#{file.path}(#{file.lineno}): #{$!}"
	  end
  # try to support loading dictionary files from FreeRADIUS
  # VENDOR    Lucent        4846  format=2,1
	when /^VENDOR\s+([-A-Za-z0-9]+)\s+(\w+)\s+[a-z,=0-9]+\s*$/
	  begin
	    storevendor([$1, $2])
	    rescue
	    raise "#{file.path}(#{file.lineno}): #{$!}"
	  end
  when /^(BEGIN|END)-TLV/
    # WiMAX Forum crap
    # ???
	when /^(BEGIN|END)-VENDOR\s+([-A-Za-z0-9]+)\s*$/
	  if(! @vendors[$2])
	    raise RadiusUtilError, "#{file.path}(#{file.lineno}): BEGIN/END-VENDOR before VENDOR token"
	  end
	  if($1 == 'BEGIN' && @be_vendor)
	    raise RadiusUtilError, "#{file.path}(#{file.lineno}): Nested BEGIN-VENDOR blocks"
	  end
	  if($1 == 'END' && ! @be_vendor)
	    raise RadiusUtilError, "#{file.path}(#{file.lineno}): END-VENDOR with no matching BEGIN-VENDOR"
	  end
	  if($1 == 'END' && $2 != @be_vendor)
	    raise RadiusUtilError, "#{file.path}(#{file.lineno}): Mismatched BEGIN/END-VENDOR tokens"
	  end
	  @be_vendor = ($1 == 'BEGIN' ? $2 : nil)
	else
	  raise RadiusUtilError, "#{file.path}(#{file.lineno}): Parse error"
	end
      end
    end

    # Store an individual attribute in the dictionary as a *Raddict* structure.
    # <em>vals</em> should be an array of pre-parsed entries: [ name, num, datatype, (vendor) ].
    def storeattrib(vals)
      if(vals[2] == 'octets')
	vals[2] = 'string'
      end
      if((! vals[3] || vals[3].empty?) && ! @be_vendor)
	@attribs[vals[0], vals[1].to_i] = Raddict.new(vals[0], vals[1].to_i, vals[2], nil)
      else
	# VSA
	vendor = ((! vals[3] || vals[3].empty?) ? @be_vendor : vals[3])
	if(! @vsa[vendor] || ! @vendors[vendor])
	  raise RadiusUtilError, "Unknown vendor #{vendor}"
	end
	@vsa[vendor][vals[0], vals[1].to_i] = Raddict.new(vals[0], vals[1].to_i, vals[2], nil)
	@vsa_name_lookup[vals[0]] = vendor
      end
    end

    # Store an individual value in the dictionary as a *RValues* structure.
    # <em>vals</em> should be an array of pre-parsed entries: [ attrname, valname, valnum ].
    def storeval(vals)
      if(vals[2] =~ /^0x/)
	vals[2] = sprintf("%d", vals[2])
      end
      if(! @values[vals[0]])
	@values[vals[0]] = [].extend(MultiHash)
      end
      @values[vals[0]][vals[1], vals[2].to_i] = RValues.new(vals[0], vals[1], vals[2].to_i)
    end

    # Store a vendor in the vendor list.
    # <em>vals</em> should be an array of pre-parsed entries: [ name, num ].
    def storevendor(vals)
      if(@vendors[vals[0]] || @vsa[vals[0]])
	raise RadiusUtilError, "Vendor #{vals[0]} already seen"
      end
      @vendors[vals[0]] = vals[1].to_i
      @vsa[vals[0], vals[1].to_i] = []
      @vsa[vals[0]].extend(MultiHash)
    end

    # Link up the :values Raddict member for each attribute with the matching
    # list of values for those attribs that have them.
    def clean
      @attribs.each_value do |v|
	v.values = @values[v.attrname]
	v.freeze
      end
      @vsa.each_value do |ven|
	ven.each_value do |v|
	  v.values = @values[v.attrname]
	  v.freeze
	end
      end
    end

    public

    # Access the dictionary in a Hash-like matter. Because of the magic of
    # *MultiHash*, attribs can be accessed either by name or by number.
    # If an attribute accessed by name is not found in the main dictionary,
    # the VSA lookup table will be consulted and a corresponding VSA, if any,
    # will be returned.
    # If set_vendor is set to a valid vendor, then only VSAs under that
    # vendor will be returned.
    def [](idx1, idx2=nil)
      if(idx2)
	@vsa[idx1][idx2]
      else
	if(@be_vendor)
	  @vsa[@be_vendor][idx1]
	elsif(@set_vendor)
	  @vsa[@set_vendor][idx1]
	elsif(@attribs[idx1])
	  @attribs[idx1]
	elsif(@vsa_name_lookup[idx1])
	  @vsa[@vsa_name_lookup[idx1]][idx1]
	end
      end
    end

    # Iterate through the dictionary, returning successive name, value
    # pairs.
    def each
      if(@be_vendor)
	dict = @vsa[@be_vendor]
      elsif(@set_vendor)
	dict = @vsa[@set_vendor]
      else
	dict = @attribs
      end
      dict.each { |k, v| yield k, v }
      self
    end

    # Exhaustive search in all dictionaries. This is probably
    # pretty slow; avoid it if possible.
    def search(&exp)
      if(! block_given?)
	raise ArgumentError, "No block given"
      end
      res = []
      @attribs.each_value do |a|
	res << a if(exp.call(a))
      end
      @vendors.each_int do |k, ven|
	@vsa[ven].each_value do |a|
	  res << a if(exp.call(a))
	end
      end

      res
    end

    # Return true if the attribute is a VSA. 
    # Note that this WILL NOT WORK with VSA attribute numbers,
    # because they overlap. Use names only.
    def is_vsa?(attr)
      return false if(@attribs[attr])
      return true if(@vsa_name_lookup[attr])
      false
    end

    # Return the vendor for a given attribute or nil if none.
    def vendor(attr)
      @vsa_name_lookup[attr]
    end

    # Custom `inspect' to keep irb from overflowing.
    def inspect
      "#<RADIUS::Dictionary \@dictfile=\"#{@dictfile}\">"
    end


    # Setting <em>:set_vendor</em> to a valid vendor name or number will
    # cause <em>[]</em> to return only attributes from that vendor's dictionary.
    # Setting it back to <em>nil</em> reverses this behavior. Defaults to <em>nil</em>.
    def set_vendor=(ven)
      if(@vendors[ven] || ven == nil)
	@set_vendor = ven
      else
	raise RadiusUtilError, "Unknown vendor #{ven}"
      end
    end
    attr_reader :set_vendor

    # Read-only access to the vendor table.
    attr_reader :vendors
  end
      
end
