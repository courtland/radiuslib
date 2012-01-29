# Radiuslib for Ruby
# Dan Debertin <airboss@nodewarrior.org>

# MultiHash is, oddly enough, actually an Array mixin, but the
# resulting behavior is more Hash-like. When mixed into an Array,
# elements added to the MultiHash can be accessed via either a
# String or Fixnum index. Either index will access the same element,
# not a copy of it. Note the (probably surprising) metaphor skew
# for the setter method -- [] requires two args between brackets,
# along with the value.
module MultiHash

  # Access MultiHash elements by name or number.
  def [](idx)
    case idx
    when Integer
      (reverse.rassoc(idx) || [])[2]
    when String
      (reverse.assoc(idx) || [])[2]
    else
      nil
    end
  end

  # Add an element to the multihash. Arguments must be ordered
  # [ String, Integer ] = AnyObject.
  def []=(idxs, idxf, val)
    if((! idxs.is_a?(String) && ! idxs.nil?) ||
       (! idxf.is_a?(Integer) && ! idxf.nil?))
      raise TypeError
    end

    # Keep "overwritten" values on the stack, but rely on use of
    # reverse.[r]assoc to ignore them. Improves speed by 50%, at
    # slight memory cost, over use of delete_if.
    push([idxs, idxf, val])
  end

  # Sort by Integer index.
  def sort_int
    sort { |a, b| a[1] <=> b[1] }
  end

  # Sort by String index.
  def sort_str
    sort { |a, b| a[0] <=> b[0] }
  end

  # Iterate in a Hash-like manner, with Integers as indexes.
  def each_int
    sort_int.each { |a| yield a[1], a[2] }
  end

  # Iterate in a Hash-like manner, with Strings as indexes.
  def each_str
    each { |a| yield a[0], a[2] }
  end

  # Iterate over the values only.
  def each_value
    each { |a| yield a[2] }
  end

  # Iterate over the Integer keys only.
  def each_int_key
    sort_int.each { |a| yield a[1] }
  end

  # Iterate over the String keys only.
  def each_str_key
    each { |a| yield a[0] }
  end

end

# Similar to MultiHash, except mutually reflexive. Auto-inverts
# depending on the index, but the "data" consists of whatever
# is the value at the time of access. 
# Note that unlike MultiHash, this is actually a Hash mixin.
module InvHash

  # Access elements by either String or Integer. If our indexes
  # are Integers and we're asked by String, we quickly invert
  # so that the current index type matches the type being asked
  # after, and vice versa.
  def [](idx)
    case idx
    when String
      replace(invert) if(keys[0].kind_of?(Integer))
    when Fixnum
      replace(invert) if(keys[0].kind_of?(String))
    else
      nil
    end

    fetch(idx) rescue nil
  end

  # Perform the same auto-inversion as in <em>[]</em>, but set
  # a value.
  def []=(idx, val)
    if(! (idx.kind_of?(String) && val.kind_of?(Fixnum)) &&
       ! (idx.kind_of?(Fixnum) && val.kind_of?(String)))
      raise TypeError
    end
    replace(invert) if(keys[0].class != idx.class)
    store(idx, val)
    self
  end
  
  # Set the index to Integer, and iterate.
  def each_int
    replace(invert) if(keys[0].kind_of?(String))
    each { |k, v| yield k, v }
  end

  # Set the index to String, and iterate.
  def each_str
    replace(invert) if(keys[0].kind_of?(Integer))
    each { |k, v| yield k, v }
  end

end


# This exception is raised on RADIUS-specific errors in the utility 
# classes (dictionary parse errors, user consistency problems, etc.)
class RadiusUtilError < StandardError; end

# This exception is raised on RADIUS-specific errors in the protocol
# classes (inconsistent packet contents, incorrect code byte, etc.)
class RadiusProtocolError < StandardError; end

# A special-purpose Struct that has all members auto-initialized
# to zero.
#--
#FIXME: re-evaluate whether these two can be re-factored away.
class ZeroStruct < Struct
  def initialize
    super
    members.each do |m|
      eval("self.#{m} = 0")
    end
    self
  end
end

# Some custom modifications to String. 
class String
  def zero?
    empty? || (self == "0")
  end

  def null?
    if(self =~ /^\0+$/)
      true
    else
      false
    end
  end
end

# Containers for dictionary data.

Raddict = Struct.new("Raddict", :attrname, :attrnum, :datatype, :values)
RValues = Struct.new("RValues", :attrname, :valname, :valnum)

# A clone of /usr/include/netdb.h's struct protoent.
Protoent = Struct.new("Protoent", :name, :aliases, :proto)

# A clone of /usr/include/netdb.h's struct servent.
Servent = Struct.new("Servent", :name, :aliases, :port, :proto)

# An Ascend binary IP filter.
RadIpFilter = ZeroStruct.new("RadIpFilter",
			     :type, :forward, :dir, :fill,
			     :srcip, :dstip, :srcmask, :dstmask,
			     :proto, :est, :srcport, :dstport,
			     :srcportcmp, :dstportcmp, :fill2)

# An Ascend binary IPX filter.
RadIpxFilter = ZeroStruct.new("RadIpxFilter",
			      :type, :forward, :dir, :fill,
			      :srcipxnet, :srcipxnode, :srcipxsock,
			      :dstipxnet, :dstipxnode, :dstipxsock,
			      :srcipxsockcmp, :dstipxsockcmp)

# An Ascend binary Generic filter.
RadGenericFilter = ZeroStruct.new("RadGenericFilter",
				  :type, :forward, :dir, :fill,
				  :offset, :len, :more, :mask,
				  :value, :cmp, :fill2)

# Byte orderings for the three types of filter.
GENERIC_PACK = "CCCCnnnCCCCCCCCCCCCCCCC"
IP_PACK = "CCCCNNCCCCnnCCCCCC"
IPX_PACK = "CCCCNCCCCCCnNCCCCCCnCC"

# Filter type macros.
RAD_FILTER_GENERIC = 0
RAD_FILTER_IP = 1
RAD_FILTER_IPX = 2

# Bidirectional lookup tables for encoding/decoding Ascend binary filters.
FORWARD = { 
  "forward" => 1,
  "drop"    => 0 }.extend(InvHash)

DIR = {
  "in" => 1,
  "out" => 0 }.extend(InvHash)

FILTYPE = {
  "generic" => RAD_FILTER_GENERIC,
  "ip" => RAD_FILTER_IP,
  "ipx" => RAD_FILTER_IPX }.extend(InvHash)

EST = {
  "est" => 1
}.extend(InvHash)

CMP = {
  "<" => 1,
  "=" => 2,
  ">" => 3,
  "!=" => 4 }.extend(InvHash)

GENCMP = {
  "=" => 0,
  "!=" => 1 }.extend(InvHash)

# From RFC2865, sec. 5.44., and RFC2866, sec. 5.13. List of attrib
# nums and an array of procs which carry the policy for each type of 
# packet.
# It's mostly irrelevant in light of how many new attribs and VSAs
# don't document their policy, but it's in the RFC, so here it is...

zero = proc { |g| (g == 0 ? true : false) }
zeroplus = proc { |g| (g >= 0 ? true : false) }
zerotoone = proc { |g| (g >= 0 && g <= 1 ? true : false) }
one = proc { |g| (g == 1 ? true : false) }

ATTRTAB = { 
  0  => [ nil, zerotoone, zerotoone, zerotoone, zerotoone, zerotoone, zerotoone ],
  1  => [ nil, zerotoone, zerotoone, zero,      zerotoone, zero,      zero      ],
  2  => [ nil, zerotoone, zero,      zero,      zero,      zero,      zero      ],
  3  => [ nil, zerotoone, zero,      zero,      zero,      zero,      zero      ],
  4  => [ nil, zerotoone, zero,	     zero,      zerotoone, zero,      zero      ],
  5  => [ nil, zerotoone, zero,	     zero,      zerotoone, zero,      zero      ],
  6  => [ nil, zerotoone, zerotoone, zero,      zerotoone, zero,      zero      ],
  7  => [ nil, zerotoone, zerotoone, zero,      zerotoone, zero,      zero      ],
  8  => [ nil, zerotoone, zerotoone, zero,      zerotoone, zero,      zero      ],
  9  => [ nil, zerotoone, zerotoone, zero,      zerotoone, zero,      zero      ],
  10 => [ nil, zero,	  zerotoone, zero,	zerotoone, zero,      zero	],
  11 => [ nil, zero,	  zeroplus,  zero,	zeroplus,  zero,      zero	],
  12 => [ nil, zerotoone, zerotoone, zero,	zerotoone, zero,      zero	],
  13 => [ nil, zeroplus,  zeroplus,  zero,	zeroplus,  zero,      zero	],
  14 => [ nil, zeroplus,  zeroplus,  zero,	zeroplus,  zero,      zero	],
  15 => [ nil, zero,	  zerotoone, zero,	zerotoone, zero,      zero	],
  16 => [ nil, zero,	  zerotoone, zero,	zerotoone, zero,      zero	],
  18 => [ nil, zero,	  zeroplus,  zeroplus,	zero,	   zero,      zeroplus  ],
  19 => [ nil, zerotoone, zerotoone, zero,	zerotoone, zero,      zero	],
  20 => [ nil, zero,	  zerotoone, zero,	zerotoone, zero,      zero	],
  22 => [ nil, zero,	  zeroplus,  zero,	zeroplus,  zero,      zero	],
  23 => [ nil, zero,	  zerotoone, zero,	zerotoone, zero,      zero	],
  24 => [ nil, zerotoone, zerotoone, zero,	zero,	   zero,      zerotoone ],
  25 => [ nil, zero,	  zeroplus,  zero,	zeroplus,  zero,      zero 	],
  26 => [ nil, zeroplus,  zeroplus,  zero,	zeroplus,  zeroplus,  zeroplus  ],
  27 => [ nil, zero,	  zerotoone, zero,	zerotoone, zero,      zerotoone ],
  28 => [ nil, zero,	  zerotoone, zero,	zerotoone, zero,      zerotoone ],
  29 => [ nil, zero,	  zerotoone, zero,	zerotoone, zero,      zero	],
  30 => [ nil, zerotoone, zero,	     zero,	zerotoone, zero,      zero	],
  31 => [ nil, zerotoone, zero,	     zero,	zerotoone, zero,      zero	],
  32 => [ nil, zerotoone, zero,	     zero,	zerotoone, zero,      zero	],
  33 => [ nil, zeroplus,  zeroplus,  zeroplus,	zeroplus,  zeroplus,  zeroplus  ],
  34 => [ nil, zerotoone, zerotoone, zero,	zerotoone, zero,      zero	],
  35 => [ nil, zerotoone, zerotoone, zero,	zerotoone, zero,      zero	],
  36 => [ nil, zerotoone, zerotoone, zero,	zerotoone, zero,      zero	],
  37 => [ nil, zero,	  zerotoone, zero,	zerotoone, zero,      zero	],
  38 => [ nil, zero,	  zeroplus,  zero,	zerotoone, zero,      zero	],
  39 => [ nil, zero,	  zerotoone, zero,	zerotoone, zero,      zero	],
  40 => [ nil, zero,	  zero,	     zero,	one,	   zero,      zero	],
  41 => [ nil, zero,	  zero,	     zero,	zerotoone, zero,      zero	],
  42 => [ nil, zero,	  zero,	     zero,	zerotoone, zero,      zero	],
  43 => [ nil, zero,	  zero,	     zero,	zerotoone, zero,      zero	],
  44 => [ nil, zero,	  zero,	     zero,	one,	   zero,      zero	],
  45 => [ nil, zero,	  zero,	     zero,	zerotoone, zero,      zero	],
  46 => [ nil, zero,	  zero,	     zero,	zerotoone, zero,      zero	],
  47 => [ nil, zero,	  zero,	     zero,	zerotoone, zero,      zero	],
  48 => [ nil, zero,	  zero,	     zero,	zerotoone, zero,      zero	],
  49 => [ nil, zero,	  zero,	     zero,	zerotoone, zero,      zero	],
  50 => [ nil, zero,	  zero,	     zero,	zeroplus,  zero,      zero	],
  51 => [ nil, zero,	  zero,	     zero,	zeroplus,  zero,      zero	],
  60 => [ nil, zerotoone, zero,	     zero,	zero,	   zero,      zero	],
  61 => [ nil, zerotoone, zero,	     zero,	zerotoone, zero,      zero	],
  62 => [ nil, zerotoone, zerotoone, zero,	zerotoone, zero,      zero	],
  63 => [ nil, zerotoone, zerotoone, zero,	zerotoone, zero,      zero	]
}
  
# "files"-only implementation of the getprotobynum() library call.
def getprotobynum(protonum)
  File.open("/etc/protocols", "r") do |f|
    f.each do |line|
      next if(line =~ /^(?:#|\s*$)/)
      line.sub!(/#.*/, "")
      if(line =~ /^([^\s]+)\s+([0-9]+)\s+([^\s]+)/)
	if($2.to_i == protonum)
	  return Protoent.new($1, $3, $2.to_i)
	end
      end
    end
  end
  nil
end

# "files"-only implementation of the getprotobyname() library call.
def getprotobyname(protoname)
  File.open("/etc/protocols", "r") do |f|
    f.each do |line|
      next if(line =~ /^(?:#|\s*$)/)
      line.sub!(/#.*/, "")
      if(line =~ /^([^\s]+)\s+([0-9]+)\s+([^\s]+)/)
	if($1.downcase == protoname.downcase)
	  return Protoent.new($1, $3, $2.to_i)
	end
      end
    end
  end
  nil
end



# "files"-only implementation of the getservbyport() library
# call. If servproto is not specified, the first match will be
# returned, regardless of protocol.
def getservbyport(servnum, servproto=nil)
  File.open("/etc/services", "r") do |f|
    f.each do |line|
      next if(line =~ /^(?:#|\s*$)/)
      line.sub!(/#.*/, "")
      if(line =~ /^([^\s]+)\s+([0-9]+)\/([A-Za-z]+)(?:\s+([^\s]+))?/)
	if($2.to_i == servnum)
	  if((servproto && $3.downcase == servproto.downcase) ||
	     (! servproto))
	    return Servent.new($1, $4, $2.to_i, $3)
	  end
	end
      end
    end
  end
  nil
end

# "files"-only implementation of the getservbyname() library call.
def getservbyname(servname, servproto=nil)
  File.open("/etc/services", "r") do |f|
    f.each do |line|
      next if(line =~ /^(?:#|\s*$)/)
      line.sub!(/#.*/, "")
      if(line =~ /^([^\s]+)\s+([0-9]+)\/([A-Za-z]+)(?:\s+([^\s]+))?/)
	if($1.downcase == servname.downcase)
	  if((servproto && $3.downcase == servproto.downcase) ||
	     (! servproto))
	    return Servent.new($1, $4, $2.to_i, $3)
	  end
	end
      end
    end
  end
  nil
end

