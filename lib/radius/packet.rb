require "radius/dictionary"
require "radius/radiusutil"
require "digest/md5"
require "continuation"

module RADIUS

  # General methods for accessing and manipulating elements of a 
  # RADIUS packet. The primary goal of these methods is to represent
  # a valid packet at all times, and to go to that packet for all
  # information -- no external hash of AV-pairs is used to track
  # what should be in the packet, as it's too hard for that to get
  # out of sync with the actual contents of the packet. Every time
  # the packet is changed, context-sensitive information is 
  # re-calculated to reflect the changes.
  module Packet
    
    class Retry < StandardError
    end

    # Packet type codes. Note that ACCESS_CHALLENGE, STAT_SRV,
    # STAT_CLNT and RSVD are unimplemented.
    ACCESS_REQUEST   = 0x01
    ACCESS_ACCEPT    = 0x02
    ACCESS_REJECT    = 0x03
    ACCT_REQUEST     = 0x04
    ACCT_RESP        = 0x05
    ACCESS_CHALLENGE = 0x0B
    STAT_SRV         = 0x0C
    STAT_CLNT        = 0x0D
    RSVD             = 0xFF

    HEADERLEN        = 20
    PACKET_MIN       = 20
    PACKET_MAX       = 4095

    @@dict = nil
    # Our module-level @@dict needs to be the including class's @@dict.
    def Packet.append_features(incomingClass)
      @@dict = incomingClass.dict

      super
    end


    ##########################################################
    # Low-level methods.
    # These methods do not access the dictionary, and operate
    # on and return raw bits of @packet.
    # 
    # All of these methods assume pre-validated input.
    ##########################################################

    private

    @@logger = nil
    # setup a logger, trying to use the rails logger, else a new one to STDOUT
    def logger
      @@logger ||= Rails.logger || Logger.new(STDOUT)
    end
    
    def each_tlv
      # Return binary TLV tuples from the attribute-list.
      avs = @packet[HEADERLEN...@packet.length]
      while(! avs.empty?)
	      len = avs[1].ord
	      yield avs[0...len]
	      avs.slice!(0...len)
      end
    end

    def each_tlv_with_index
      # Return binary TLV tuples, along with the tuple's
      # position relative to the beginning of the packet.
      avs = @packet[HEADERLEN...@packet.length]
      loc = HEADERLEN
      while(! avs.empty?)
	      len = avs[1].ord
	      yield loc, avs[0...len]
	      loc += len
	      avs.slice!(0...len)
      end
    end

    # Count the number of times an attrib appears in the packet.
    def count(attr)
      tot = 0
      each_tlv do |a| 
        tot += 1 if(a[0].ord == attr)
      end
      tot
    end

    def pairget(attr, val)
      # Returns an array of all TLV tuples where T == attr
      # and V == val.
      results = []
      each_tlv do |a|
	      results << [ a[0].ord, a[2...a[1].ord] ] if(a[0].ord == attr && a[2...a[1].ord] == val)
      end

      results
    end

    def attrget(attr)
      # Returns an array of all TLV tuples where T == attr.
      results = []
      each_tlv do |a|
	      results << [ a[0].ord, a[2...a[1].ord] ] if(a[0].ord == attr)
      end

      results
    end

    def pairadd(attr, val)
      # Adds a pair to the packet.
      # Check ATTRTAB in case this attr has limits on how many times it
      # can appear (if at all) in this packet.
      if((ATTRTAB[attr] && ATTRTAB[attr][@packet[0].ord].call(count(attr) + 1)) ||
	 ! ATTRTAB[attr])
	@packet += [attr << 8 | val.length + 2].pack("n") + val
      else
	raise RadiusProtocolError, "Attribute #{attr} should not appear #{count(attr) + 1} time(s) in this packet"
      end
      recalc_packet
      @packet
    end

    def pairdel(attr, val)
      # Delete an attribute with a specified value from the packet.
      begin
        each_tlv_with_index do |i, a|
        	if(a[0].ord == attr && a[2...a[1].ord] == val)
        	  @packet = @packet[0...i] + @packet[i + a.length...@packet.length]
        	  # We're modifying what each_tlv is iterating over, so we need
        	  # to start over...
        	  raise Retry
        	end
        end
      rescue Retry
        retry
      end
      
      recalc_packet

      @packet
    end

    def attrdel(attr)
      # Delete all occurrences of an attribute.
      begin
        each_tlv_with_index do |i, a|
      	  if(a[0].ord == attr)
      	    @packet = @packet[0...i] + @packet[i + a.length...@packet.length]
      	    raise Retry
      	  end
        end
      rescue Retry
        retry
      end
      
      recalc_packet

      @packet
    end

    def clear(type)
      # Erase the entire packet and re-initialize it.
      srand(Time.now.to_i + $$)
      # We don't need high-quality randomness for the identifier.
      @packet = ''
      @packet += [type << 8 | rand(255), 0].pack("nn")
      @packet += [0, 0, 0, 0].pack("NNNN")
      recalc_packet

      @packet
    end

    def recalc_packet
      # Global recalculation tasks to be performed when @packet changes.
      @packet[2..3] = [@packet.length].pack("n")
      valid_packet?(@packet)
    end

    def replace(data)
      # Take a packet and import it into self
      if(valid_packet?(data))
	@packet = data
	recalc_packet
      end
    end
      
    ########################################################
    # Bridge methods.
    # The following methods convert between machine-readable
    # data representations and human- or programmer-readable
    # representations.
    #
    # All of these methods assume pre-validated input, apart
    # from the two whose purpose it is to validate input.
    ########################################################

    def pack16(num)
      # Pack a 16-byte Bignum into a binary string.
      d = []
      4.times { |i| d.unshift((num >> i * 32) & 0xffffffff) }
      return d.pack("NNNN")
    end

    def unpack16(str)
      # Unpack a 16-byte string into a Bignum.
      str.bytes.inject {|a, b| (a << 8) + b }
    end

    # Convert an IP address represented as 4 1-byte chars
    # into a dotted-quad-notation string.
    def ipaddr_bin2str(val)
      d = []
      val.each_byte { |b| d << b }
      d.join('.')
    end

    # Convert an IP address represented as either a
    # dotted-quad-notation or hex number into a 32-bit binary number.
    def ipaddr_str2bin(val)
      if(val =~ /^(?:(?:[01]?\d\d?|2[0-4]\d|25[0-5])\.?){4}$/)
	val.split(/\./).collect { |o| o.to_i }.pack("CCCC")
      elsif(val =~ /^0x[0-9A-Fa-f]{8}$/)
	[sprintf("%d", val).to_i].pack("N")
      else
	raise RadiusProtocolError, "IP address format violation: #{val}"
      end
    end

    # Convert a dotted-quad or hex IP address to a 32-bit number.
    def ipaddr_str2num(val)
      unpack16(ipaddr_str2bin(val))
    end

    # Convert a 32-bit number to a dotted-quad IP address.
    def ipaddr_num2str(val)
      d = []
      val.each_byte { |b| d << b }
      d.join('.')
    end
    
    # Translate human-readable filter syntax to Ascend binary format. 
    def abin_encode(filstr)
      fil_fields = filstr.split(/\s+/)
      filter = nil
      case fil_fields[0]
      when 'ip'
	filter = RadIpFilter.new
	abin_encode_ipfil(fil_fields, filter)
	filter = filter.to_a.flatten.pack(IP_PACK)
      when 'ipx'
	filter = RadIpxFilter.new
	abin_encode_ipxfil(fil_fields, filter)
	filter = filter.to_a.flatten.pack(IPX_PACK)
      when 'generic'
	filter = RadGenericFilter.new
	abin_encode_genericfil(fil_fields, filter)
	filter = filter.to_a.flatten.pack(GENERIC_PACK)
      else
	raise RadiusProtocolError, "Unknown filter type #{fil_fields[0]}"
      end
      while(filter.length != 32)
	filter += "\0"
      end
      filter
    end

    # Encode the IP-specific parts of an Ascend binary filter.
    def abin_encode_ipfil(fil_fields, filter)
      # First four fields will always be the same.
      filter.type = FILTYPE[fil_fields.shift]
      filter.dir = DIR[fil_fields.shift]
      filter.forward = FORWARD[fil_fields.shift]
      # IP-specific
      while(! fil_fields.empty?)
	f = fil_fields.shift
	if(f == 'dstip')
	  ip, mask = fil_fields.shift.split(/\//)
	  # ipaddr_* throw their own exceptions.
	  ip = ipaddr_str2num(ip)
	  # Assume /32 if no mask.
	  mask = (mask ? mask.to_i : 32)
	  if(mask < 0 || mask > 32)
	    raise RadiusProtocolError, "Illogical mask for #{ip}"
	  end
	  filter.dstip = ip
	  filter.dstmask = mask
	elsif(f == 'srcip')
	  ip, mask = fil_fields.shift.split(/\//)
	  ip = ipaddr_str2num(ip)
	  mask = ( mask ? mask.to_i : 32)
	  if(mask < 0 || mask > 32)
	    raise RadiusProtocolError, "Illogical mask for #{ip}"
	  end
	  filter.srcip = ip
	  filter.srcmask = mask
	elsif(f == 'est')
	  filter.est = EST[f]
	elsif(f == 'dstport')
	  cmp = CMP[fil_fields.shift]
	  port = fil_fields.shift
	  if(port =~ /^[0-9]+$/)
	    port = port.to_i
	  else
	    port = getservbyname(port).port
	  end
	  if(! cmp || ! port)
	    raise RadiusProtocolError, "Unknown tokens: #{cmp}, #{port}"
	  end
	  filter.dstportcmp = cmp
	  filter.dstport = port
	elsif(f == 'srcport')
	  cmp = CMP[fil_fields.shift]
	  port = fil_fields.shift
	  if(port =~ /^[0-9]+$/)
	    port = port.to_i
	  else
	    port = getservbyname(port).port
	  end
	  if(! cmp || ! port)
	    raise RadiusProtocolError, "Unknown tokens: #{cmp}, #{port}"
	  end
	  filter.srcportcmp = cmp
	  filter.srcport = port
	else
	  # Proto doesn't have a keyword. grrr.
	  if(f =~ /^[0-9]+$/)
	    filter.proto = getprotobynum(f.to_i).proto
	  elsif(getprotobyname(f))
	    filter.proto = getprotobyname(f).proto
	  else
	    raise RadiusProtocolError, "Unknown keyword #{f}"
	  end
	end
      end
      filter.fill2 = [ 0, 0, 0, 0 ]
      filter
    end

    # Encode the IPX-specific parts of an Ascend binary filter.
    def abin_encode_ipxfil(fil_fields, filter)
      filter.type = FILTYPE[fil_fields.shift]
      filter.dir = DIR[fil_fields.shift]
      filter.forward = FORWARD[fil_fields.shift]
      # IPX-specific. Keep in mind, I don't know the first thing
      # about IPX.
      while(! fil_fields.empty?)
	f = fil_fields.shift
	if(f == 'srcipxnet')
	  ipxnet = fil_fields.shift
	  if(ipxnet !~ /^[0-9A-Fa-f]{1,8}$/)
	    raise RadiusProtocolError, "IPX Network format violation: #{ipxnet}"
	  end
	  filter.srcipxnet = sprintf("%d", "0x#{ipxnet}").to_i
	elsif(f == 'srcipxnode')
	  ipxnode = fil_fields.shift
	  if(ipxnode !~ /^[0-9A-Fa-f]{1,12}$/)
	    raise RadiusProtocolError, "IPX Node format violation: #{ipxnode}"
	  end
	  filter.srcipxnode = []
	  while(! ipxnode.empty?)
	    filter.srcipxnode.push(sprintf("%d", "0x#{ipxnode.slice!(0..1)}").to_i)
	  end
	  6.times do |i| 
	    if(filter.srcipxnode[i].nil?)
	      filter.srcipxnode[i] = 0
	    end
	  end
	elsif(f == 'srcipxsock')
	  filter.srcipxsockcmp = CMP[fil_fields.shift]
	  filter.srcipxsock = sprintf("%d", "0x#{fil_fields.shift}").to_i
	  if(! filter.srcipxsockcmp || ! filter.srcipxsock)
	    raise RadiusProtocolError, "Socket notation not understood for #{f}"
	  end
	elsif(f == 'dstipxnet')
	  ipxnet = fil_fields.shift
	  if(ipxnet !~ /^[0-9A-Fa-f]{1,8}$/)
	    raise RadiusProtocolError, "IPX Network format violation: #{ipxnet}"
	  end
	  filter.dstipxnet = sprintf("%d", "0x#{ipxnet}").to_i      
	elsif(f == 'dstipxnode')
	  ipxnode = fil_fields.shift
	  if(ipxnode !~ /^[0-9A-Fa-f]{1,12}$/)
	    raise RadiusProtocolError, "IPX Node format violation: #{ipxnode}"
	  end
	  filter.dstipxnode = []
	  while(! ipxnode.empty?)
	    filter.dstipxnode.push(sprintf("%d", "0x#{ipxnode.slice!(0..1)}").to_i)
	  end
	  6.times do |i| 
	    if(filter.dstipxnode[i].nil?)
	      filter.dstipxnode[i] = 0
	    end
	  end
	elsif(f == 'dstipxsock')
	  filter.dstipxsockcmp = CMP[fil_fields.shift]
	  filter.dstipxsock = sprintf("%d", "0x#{fil_fields.shift}").to_i
	  if(! filter.dstipxsockcmp || ! filter.dstipxsock)
	    raise RadiusProtocolError, "Socket notation not understood for #{f}"
	  end
	end
      end
      filter
    end

    # Encode "generic" Ascend binary filters.
    def abin_encode_genericfil(fil_fields, filter)
      filter.type = FILTYPE[fil_fields.shift]
      filter.dir = DIR[fil_fields.shift]
      filter.forward = FORWARD[fil_fields.shift]
      # No keywords.
      filter.offset = fil_fields.shift.to_i
      filter.mask = []
      mask = fil_fields.shift
      strmask = mask.dup
      while(! strmask.empty?)
	filter.mask.push(sprintf("%d", "0x#{strmask.slice!(0..1)}").to_i)
      end
      # mask and value are both arrays of bytes, 6 chars long.
      if(filter.mask.size > 6)
	raise RadiusProtocolError, "mask too long"
      end
      value = fil_fields.shift
      strval = value.dup
      filter.value = []
      while(! strval.empty?)
	filter.value.push(sprintf("%d", "0x#{strval.slice!(0..1)}").to_i)
      end
      if(filter.value.size > 6)
	raise RadiusProtocolError, "value too long"
      end
      filter.len = filter.value.size
      if(filter.value.length != filter.mask.length)
	raise RadiusProtocolError, "mask length doesn't match value length"
      end
      # Pad both out to 6 bytes.
      while(filter.mask.size != 6)
	filter.mask.push(0)
      end
      while(filter.value.size != 6)
	filter.value.push(0)
      end
      filter.cmp = GENCMP[fil_fields.shift]
      filter.more = (fil_fields.shift.nil? ? 0 : 1)
      filter.fill2 = [ 0, 0, 0 ]
      filter
    end

    # Translate an Ascend binary filter to its human-readable representation.
    def abin_decode(binfil)
      case binfil[0]
      when RAD_FILTER_IP
	filter = RadIpFilter.new
	abin_decode_ipfil(binfil, filter)
	filstr = [filter.type, filter.dir, filter.forward,
	  (filter.dstip.zero? ? "" :
	   "dstip " + filter.dstip + "/" + filter.dstmask),
	  (filter.srcip.zero? ? "" :
	   "srcip " + filter.srcip + "/" + filter.srcmask),
	  (filter.proto.zero? ? "" : filter.proto),
	  (filter.dstport.zero? ? "" :
	   "dstport " + filter.dstportcmp + " " + filter.dstport),
	  (filter.srcport.zero? ? "" :
	   "srcport " + filter.srcportcmp + " " + filter.srcport),
	  (filter.est.zero? ? "" : filter.est)].join(' ')
      when RAD_FILTER_IPX
	filter = RadIpxFilter.new
	abin_decode_ipxfil(binfil, filter)
	filstr = [filter.type, filter.dir, filter.forward,
	  (filter.srcipxnet.zero? ? "" :
	   "srcipxnet " + filter.srcipxnet +
	   (filter.srcipxnode.zero? ? "" :
	    " srcipxnode " + filter.srcipxnode +
	    (filter.srcipxsock.zero? ? "" :
	     " srcipxsock " + filter.srcipxsockcmp + " " + filter.srcipxsock))) + " ",
	  (filter.dstipxnet.zero? ? "" :
	   "dstipxnet " + filter.dstipxnet +
	   (filter.dstipxnode.zero? ? "" :
	    " dstipxnode " + filter.dstipxnode +
	    (filter.dstipxsock.zero? ? "" :
	     " dstipxsock " + filter.dstipxsockcmp + " " + filter.dstipxsock)))].join(' ')
      when RAD_FILTER_GENERIC
	filter = RadGenericFilter.new
	abin_decode_genericfil(binfil, filter)
	filstr = [filter.type, filter.dir, filter.forward,
	  filter.offset, filter.mask, filter.value,
	  (filter.cmp.zero? ? "" : filter.cmp),
	  (filter.more.zero? ? "" : filter.more)].join(' ')
      else
        raise RadiusProtocolError, "Invalid Ascend binary filter: #{binfil}"
      end

      filstr.squeeze(" ")
    end

    # Decode an Ascend IP Filter.
    def abin_decode_ipfil(binfil, filter)
      filter.type = FILTYPE[binfil[0]]
      filter.forward = FORWARD[binfil[1]]
      filter.dir = DIR[binfil[2]]
      filter.srcip = (binfil[4..7].null? ? 0 : ipaddr_bin2str(binfil[4..7]))
      filter.dstip = (binfil[8..11].null? ? 0 : ipaddr_bin2str(binfil[8..11]))
      filter.srcmask = (binfil[12] == 0 ? 0 : binfil[12].to_s)
      filter.dstmask = (binfil[13] == 0 ? 0 : binfil[13].to_s)
      filter.proto = (binfil[14] == 0 ? 0 : getprotobynum(binfil[14]).name)
      filter.est = EST[binfil[15]] || 0
      srcport = binfil[16..17].unpack("n")[0]
      if(filter.proto.zero?)
	srv = getservbyport(srcport)
	filter.srcport = (srv ? srv.name : srcport.to_s)
      else
	srv = getservbyport(srcport, filter.proto)
	filter.srcport = (srv ? srv.name : srcport.to_s)
      end
      dstport = binfil[18..19].unpack("n")[0]
      if(filter.proto.zero?)
	srv = getservbyport(dstport)
	filter.dstport = (srv ? srv.name : dstport.to_s)
      else
	srv = getservbyport(dstport, filter.proto)
	filter.dstport = (srv ? srv.name : dstport.to_s)
      end
      filter.srcportcmp = CMP[binfil[20]]
      filter.dstportcmp = CMP[binfil[21]]
      
      filter
    end

    # Decode an Ascend IPX filter.
    def abin_decode_ipxfil(binfil, filter)
      filter.type = FILTYPE[binfil[0]]
      filter.forward = FORWARD[binfil[1]]
      filter.dir = DIR[binfil[2]]
      filter.srcipxnet = sprintf("%x", *binfil[4..7].unpack("N"))
      if(binfil[8..13] !~ /^\0+$/)
	filter.srcipxnode = ""
	binfil[8..13].each_byte do |n|
	  filter.srcipxnode += sprintf("%x", n)
	end
      end
      filter.srcipxsock = sprintf("%x", binfil[14..15].unpack("n")[0].to_s)
      filter.dstipxnet = sprintf("%x", *binfil[16..19].unpack("N"))
      if(binfil[20..25] !~/^\0+$/)
	filter.dstipxnode = ""
	binfil[20..25].each_byte do |n|
	  filter.dstipxnode += sprintf("%x", n)
	end
      end
      filter.dstipxsock = sprintf("%x", binfil[26..27].unpack("n")[0].to_s)
      filter.srcipxsockcmp = CMP[binfil[28]]
      filter.dstipxsockcmp = CMP[binfil[29]]

      filter
    end

    # Decode an Ascend "generic" filter.
    def abin_decode_genericfil(binfil, filter)
      filter.type = FILTYPE[binfil[0]]
      filter.forward = FORWARD[binfil[1]]
      filter.dir = DIR[binfil[2]]
      filter.offset = binfil[4..5].unpack("n")[0].to_s
      filter.len = binfil[6..7].unpack("n")[0].to_s
      filter.more = *binfil[8..9].unpack("n")[0]
      filter.more = "more" if(! filter.more.zero?)
      filter.mask = ""
      binfil[10..15].unpack("CCCCCC").each do |n|
	filter.mask += sprintf("%x", n)
      end
      filter.value = ""
      binfil[16..21].unpack("CCCCCC").each do |n|
	filter.value += sprintf("%x", n)
      end
      filter.cmp = GENCMP[binfil[22]]

      filter
    end

    # Convert raw attribute type codes into Raddict/RValues
    # structures. 
    def int2dict(attr, val)
      @@dict.set_vendor = nil
      if(! @@dict[attr])
	# Make up a "fake" attribute if it's not in the dict.
	attr = Raddict.new("Attr-#{attr}", attr, 'string', nil)
      else
	attr = @@dict[attr]
	begin
	  case attr.datatype
	  when 'string'
	    if(attr.attrnum == 26 && ! @@dict.set_vendor)
	      # VSA
	      ven, code, len = val.scan(/^V([0-9]+):T([0-9]+):L([0-9]+):/)[0].collect do |f|
		f.to_i
	      end
	      vsaval = val.sub(/^V[0-9]+:T[0-9]+:L[0-9]+:/, "")
	      if(@@dict.vendors[ven] && @@dict[ven, code])
		@@dict.set_vendor = ven
		attr = @@dict[code]
		val = vsaval
		# Bounce back to the top of this case and eval again.
		raise RuntimeError  # Sort of kludgey...
	      end
	    else
	      # Leave strings as-is if !vsa.
	    end
	  when 'integer'
	    val = val.unpack("N")[0]
	    if(attr.values && attr.values[val])
	      val = attr.values[val]
	    end
	  when 'date'
	    val = val.unpack("N")[0]
	  when 'ipaddr'
	    val = ipaddr_bin2str(val)
	  when 'abinary'
	    val = abin_decode(val)
	  end
	rescue RuntimeError
	  # We found a VSA, and need to re-evaluate based on the
	  # new value of attr & val.
	  retry
	end
      end
      @@dict.set_vendor = nil
      return [attr, val]
    end

    # Convert any kind of dictionary reference (attrname, attrnum,
    # etc.) into an int. Perform format conversion from human-readable
    # format to wire.  Translate VSAs into something packval
    # understands.  This routine raises RadiusProtocolException on
    # error, since it is commonly used to write information to the
    # packet.
    def dict2int(attr, val=nil)
      if(@@dict.is_vsa?(attr))
	@@dict.set_vendor = @@dict.vendor(attr)
      end
      if(! attr.is_a?(Struct::Raddict))
	if(! attr = @@dict[attr])
	  raise RadiusProtocolError, "Unknown attribute #{attr}"
	end
      end
      begin
	if(val)
	  case attr.datatype
	  when 'string'
	    val.force_encoding('binary')
	  when 'integer'
	    if(attr.values && attr.values[val])
	      val = attr.values[val].valnum
	    end
	    val = [val].pack("N")
	  when 'date'
	    val = [val].pack("N")
	  when 'ipaddr'
	    val = ipaddr_str2bin(val)
	  when 'abinary'
	    val = abin_encode(val)
	  end
	end
	if(@@dict.set_vendor)
	  ven = @@dict.set_vendor
	  if(ven !~ /^[0-9]+$/)
	    # Swap if we have the vendor name.
	    ven = @@dict.vendors[ven]
	  end
	  # Translate to the intermediate "packval" format. If we didn't
	  # get a value (i.e., this is a query about an attribute without
	  # a value), only V and T matter, so pack the rest with junk.
	  if(val)
	    val = "V#{ven}:T#{attr.attrnum}:L#{val.length + 2}:#{val}"
	  else
	    val = "V#{ven}:T#{attr.attrnum}:L0:EMPTY"
	  end
	  @@dict.set_vendor = nil
	  attr = @@dict[26]
	  raise RuntimeError
	end
      rescue RuntimeError
	retry
      end  
      attr = attr.attrnum
      [attr, val]
    end
	
    # Pack an attribute into wire format. Handle VSA.
    def packval(attr, val)
      if(attr == 26)
	ven, type, len = *val.scan(/^V([0-9]+):T([0-9]+):L([0-9]+):/)[0].collect do |i|
	  i.to_i
	end
	vsaval = val.sub(/^V[0-9]+:T[0-9]+:L[0-9]+:/, "")
	if(ven == 429)
	  # USR
	  val = [ven, type].pack("NN") + vsaval
	else
	  val = [ven, type, len].pack("NCC") + vsaval
	end
      end
      return [attr, val]
    end

    # Unpack a value. This method will simply return val (i.e., do
    # nothing) unless the val is itself in need of unpacking.
    # Vendor-Specific and CHAP-Password are the only two attribs that
    # have internal format that requires unpacking at this time.
    def unpackval(attr, val)
      if(attr == 26)
	# Take a rough guess as to whether this is a USR VSA...
	if(val[0..3].unpack("N")[0] == 429)
	  ven, code = *val[0..7].unpack("NN")
	  val = "V#{ven}:T#{code}:L#{val.length}:#{val[8...val.length]}"
	else
	  ven, code, len = *val[0..5].unpack("NCC")
	  val = "V#{ven}:T#{code}:L#{len}:#{val[6...len + 6]}"
	end
      elsif(attr == 3)
	# User's CHAP response is always 16 bytes beyond the CHAP ID.
	chapid, chapresp = *val.unpack("CN")
	val = "I#{chapid}:R#{chapresp}"
      end

      [attr, val]
    end
	


    # Run a sanity check on the packet and throw exceptions if
    # illogical values or inconsistencies are found.
    def valid_packet?(data)
      if(data[0].ord >= 0x0B)
	raise RadiusProtocolError, "Unknown or unsupported packet type #{data[0].ord}"
      end
      if(data[2..3].unpack("n")[0] != data.length)
	raise RadiusProtocolError, "Packet length field != actual length"
      end
      if(data.length < PACKET_MIN || data.length > PACKET_MAX)
	raise RadiusProtocolError, "Packet length out of acceptable range"
      end
      avs = data[20...data.length]
      acount = []
      while(! avs.empty?)
	acount[avs[0].ord] ||= 0
	acount[avs[0].ord] += 1
	a, v = avs[0].ord, avs[2...avs[1].ord]
	a, v = *int2dict(*unpackval(a, v))
	if(! @@dict[a.attrname])
	  raise RadiusProtocolError, "Unknown attribute #{a.attrname}"
	end
        if(@@dict[a.attrname].datatype == 'integer')
          if(@@dict[a.attrname].values && 
             (! v.is_a?(Struct::RValues) || ! @@dict[a.attrname].values[v.valnum]))
            # raise RadiusProtocolError, "Attribute #{a.attrname} value unknown: #{v}"
            logger.warn "RadiusProtocolWarning: Attribute #{a.attrname} value unknown: #{v}"
          end
        end
        if(avs[1].ord != avs[0...avs[1].ord].size)
          # raise RadiusProtocolError, "Attribute #{a.attrname} length field != actual length: #{avs[0].ord}"
          logger.warn "RadiusProtocolWarning: Attribute #{a.attrname} length field != actual length: #{avs[0].ord}"
        end
        if(avs[0].ord == 26 && avs[2..5].unpack("N")[0] != 429)
	  # VSA length field, for vendors that have it.
	  if(avs[7].ord != avs[1].ord - 6)
            # raise RadiusProtocolError, "VSA #{a.attrname} length field != actual VSA length: #{avs[0...avs[1].ord]}"
            logger.warn "RadiusProtocolWarning: VSA #{a.attrname} length field != actual VSA length: #{avs[0...avs[1].ord]}"
	  end
        end
        if(ATTRTAB[avs[0].ord] && ! ATTRTAB[avs[0].ord][data[0].ord].call(acount[avs[0].ord]))
          # raise RadiusProtocolError, "Attribute #{a.attrname} should not appear #{acount[avs[0]]} times in this packet"
          logger.warn "RadiusProtocolWarning: Attribute #{a.attrname} should not appear #{acount[avs[0].ord]} times in this packet"
        end
	avs.slice!(0...avs[1].ord)
      end #while
      true
    end

    public

    # Return the packet's code byte.
    def code
      @packet.dup[0].ord
    end

    # Return the packet's identifier byte.
    def ident
      @packet.dup[1].ord
    end

    # Return the packet's request/response authenticator as a
    # Bignum (128-bit number).
    def authen
      unpack16(@packet[4..19])
    end

    # Return the packet's request/response authenticator as a
    # binary String.
    def authen_str
      @packet.dup[4..19].to_s
    end

    # Return the "length" field from the packet. This is not a 
    # synonym for <em>size</em>!
    def length
      @packet[2..3].unpack("n")[0]
    end

    # Return the length of the packet as reported by String#length.
    # This is not a synonym for <em>length</em>!
    def size
      @packet.length
    end

    # Return a value from the packet. The index can be either the
    # attribute name or number, although VSAs should only be accessed
    # by name. VSAs can be accessed by simply using the attribute
    # name as the index, NOT 'Vendor-Specific'/26.
    # When there is an option (integer datatype and list of possible
    # values present), we will choose the representation that matches
    # the datatype of the index given.
    # This method returns an <em>Array</em> of values, even when there
    # is only one value. This is done because it is possible (common, even)
    # to have multiple instances of an attribute in a packet.
    def [](idx)
      return nil if(! @@dict[idx])
	vals = attrget(*packval(*dict2int(idx))[0])
	res = []
	vals.each do |v|
	  myres = int2dict(*unpackval(*v))
	  if(idx.is_a?(Integer))
	    if(idx == myres[0].attrnum)
	      if(myres[1].is_a?(Struct::RValues))
		res << myres[1].valnum
	      else
		res << myres[1]
	      end
	    end
	  elsif(idx.is_a?(String))
	    if(idx == myres[0].attrname)
	      if(myres[1].is_a?(Struct::RValues))
		res << myres[1].valname
	      else
		res << myres[1]
	      end
	    end
	  end
	end
      (res.empty? ? nil : res)
    end
	
    # Add an attribute to a packet.
    def []=(attr, val)
      pairadd(*packval(*dict2int(attr, val)))
    end

    # Return a copy of the binary String representing the packet.
    def to_s
      @packet.dup
    end

    # Return a hash of arrays containing the AV-pairs.
    def to_h
      phash = {}
      eachbyname do |a, v|
	phash[a] ||= []
	phash[a] << v
      end

      phash
    end

    # Return an array of attributes present in the packet. Duplicate
    # attributes are suppressed.
    def attribs
      attrib = []
      eachbyname { |a, v| attrib << a }

      attrib.uniq
    end

    alias keys attribs
    alias attributes attribs

    # Return an array of values present in the packet.
    def values
      val = []
      eachbyname { |a, v| val << v }

      val
    end
    
    alias vals values

    # Iterate through AV-pairs by number.
    def eachbynum
      each_tlv do |t|
      	a, v = *int2dict(*unpackval(t[0].ord, t[2...t[1].ord]))
      	yield a.attrnum, (v.is_a?(Struct::RValues) ? v.valnum : v)
      end
    end

    # Iterate through AV-pairs by name.
    def eachbyname
      each_tlv do |t|
	      a, v = *int2dict(*unpackval(t[0].ord, t[2...t[1].ord]))
	      yield a.attrname, (v.is_a?(Struct::RValues) ? v.valname : v)
      end
    end

    # I'll take a risk and guess that most people want to access
    # attribs by name...
    alias each eachbyname



    # Delete all occurrences of an attribute from the packet.
    def delete(key)
      # This would be so simple if it weren't for VSAs...
      return nil if(! @@dict[key])
      if(! @@dict.is_vsa?(key))
	attrdel(@@dict[key].attrnum)
      else
	del = attrget(26)
	del.each do |d|
	  attr = int2dict(*unpackval(*d))
	  if(@@dict[key].attrnum == attr[0].attrnum)
	    pairdel(*d)
	  end
	end
      end
    end

    # Delete occurrences of a specific attribute/value pair
    # from the packet.
    def delete_pair(key, val)
      if(@@dict.is_vsa?(key))
	@@dict.set_vendor = @@dict.vendor(key)
      end
      pairdel(*packval(*dict2int(key, val)))
    end
  end


  # Provides an object-oriented interface to RADIUS authentication packets.
  # Can be instantiated either empty (no attributes), or an existing
  # RADIUS packet (received from a remote client or server, for example)
  # can be imported, provided it passes certain validity tests.
  class AuthPacket

    PORT = 1812

    def AuthPacket.dict
      @@dict
    end

    # Set up either a new, clean packet, or an already-processed packet.
    # 'dict' can be either a RADIUS::Dictionary object, or the filename
    # of a dictionary -- we will instantiate a new dictionary if the latter.
    # 'code' can be either RADIUS::Packet::ACCESS_REQUEST (1), 
    # RADIUS::Packet::ACCESS_ACCEPT (2), or RADIUS::Packet::ACCESS_REJECT(3).
    # 'secret' is the shared secret between you and the remote client/server.
    # The optional 'data' argument, if present, should be a String containing
    # binary data to be imported as a new RADIUS Packet. The code byte in this
    # packet will override whatever you specify in 'code'.
    def initialize(dict, code, secret, data=nil)
      if(dict.is_a?(RADIUS::Dictionary))
	@@dict = dict
      else
	@@dict = RADIUS::Dictionary.new(dict)
      end

      AuthPacket.class_eval("include Packet")

      @secret = secret
      if(data)
	replace(data)
      else
	clear(code)
      end
      
      # Each packet type has its own authenticator calculation scheme.
      if(code == ACCESS_REQUEST)
	instance_eval <<-EOD
	# Calculate a new request authenticator once only.
	# This is just a 128-bit random number, taken from whatever
	# sources are available.
	def calc_authen
	  return if(@packet[4..19] !~ /^\0+$/)
	  if(FileTest.readable?("/dev/urandom"))
	    @packet[4..19] = File.open("/dev/urandom", "r") { |f| f.read(16) }
	  else
	    srand(Time.now.to_i + $$)
	    num = 0
	    16.times { |i| num |= rand(255) << i * 8 }
	    @packet[4..19] = pack16(num)
	  end
	end

	def recalc_packet
	  super
	  calc_authen
	end
	EOD
      elsif(code == ACCESS_ACCEPT || code == ACCESS_REJECT)
	@req_authen = nil
	instance_eval <<-EOD
	# Calculate the MD5 hash per RFC2865, sec. 3.
	# Note that we need access to the original request
	# authenticator in order to generate a response authenticator.
	# You can pass this information in via the response_to method.
	def calc_authen
	  if(! @req_authen)
	    return false
	  end
	  @packet[4..19] = Digest::MD5.digest(@packet[0..3] +
				      pack16(@req_authen) +
				      @packet[20...@packet.size] +
				      @secret)
	end
	def recalc_packet
	  super
	  calc_authen
	end
	EOD
      else
	raise RadiusProtocolError, "Wrong packet type for this class, or unsupported packet type"
      end
      recalc_packet
    end

    # Process and store the request authenticator, in one of many
    # possible forms. This information is used to calculate the
    # response authenticator, and should only be set in ACCESS_ACCEPT,
    # ACCESS_REJECT, and ACCESS_CHALLENGE packets.  (this should not
    # be taken as a sign that I support ACCESS_CHALLENGE.  I don't.)
    # IMPORTANT: If you just pass this method the RA, without the rest
    # of the packet, it won't be able to match up the identifier
    # field. This can cause strange problems.  You're best off passing
    # in either a binary String containing the entire request packet,
    # or a RADIUS::AuthPacket object.
    def response_to(ra)
      case ra
      when Integer
	@req_authen = ra
      when String
	if(valid_packet?(ra))
	  if(ra[0].ord != ACCESS_REQUEST)
	    raise ArgumentError, "Not an ACCESS_REQUEST packet: String"
	  end
	  @req_authen = unpack16(ra[4..19])
	  @packet[1] = ra[1]
	elsif(ra.length == 16)
	  @req_authen = unpack16(ra)
	else
	  raise ArgumentError, "I have no idea what that is"
	end
      when RADIUS::Packet
	if(ra.code != ACCESS_REQUEST)
	  raise ArgumentError, "Not an ACCESS_REQUEST packet: RADIUS::Packet"
	end
	@req_authen = ra.authen
	@packet[1] = ra.ident.chr
      end

      recalc_packet
    end

    class << self
      # Alternate constructor. Instantiates a new ACCESS_REQUEST packet.
      # If the 'data' argument is present, it must be a valid ACCESS_REQUEST
      # packet.
      def access_request(dict, secret, data=nil)
	if(data)
	  if(! data.is_a?(String) && ! data.is_a?(RADIUS::AuthPacket))
	    raise ArgumentError, "Invalid input data argument type \"#{data.class}\""
	  end
	  if((data.is_a?(String) && data[0].ord != RADIUS::Packet::ACCESS_REQUEST) ||
	     (data.is_a?(RADIUS::AuthPacket) && data.code != RADIUS::Packet::ACCESS_REQUEST))
	    raise ArgumentError, "Not an ACCESS_REQUEST packet"
	  end
	end

	new(dict, RADIUS::Packet::ACCESS_REQUEST, secret, data)
      end

      # Alternate constructor. Instantiates a new ACCESS_ACCEPT packet.
      # If the 'data' argument is present, it must be a valid ACCESS_ACCEPT
      # packet.
      def access_accept(dict, secret, data=nil, request=nil)
	if(data)
	  if(! data.is_a?(String) && ! data.is_a?(RADIUS::AuthPacket))
	    raise ArgumentError, "Invalid input data argument type \"#{data.class}\""
	  end
	  if((data.is_a?(String) && data[0].ord != RADIUS::Packet::ACCESS_ACCEPT) ||
	     (data.is_a?(RADIUS::AuthPacket) && data.code != RADIUS::Packet::ACCESS_ACCEPT))
	    raise ArgumentError, "Not an ACCESS_ACCEPT packet"
	  end
	end

	if(request)
	  t = new(dict, RADIUS::Packet::ACCESS_ACCEPT, secret, data)
	  # The new packet's response_to should throw its own exceptions, so no need to
	  # check the request.n
	  t.response_to(request)
	  t
	else
	  new(dict, RADIUS::Packet::ACCESS_ACCEPT, secret, data)
	end
      end

      # Alternate constructor. Instantiates a new ACCESS_REJECT packet.
      # If the 'data' argument is present, it must be a valid ACCESS_REJECT
      # packet.
      def access_reject(dict, secret, data=nil, request=nil)
	if(data)
	  if(! data.is_a?(String) && ! data.is_a?(RADIUS::AuthPacket))
	    raise ArgumentError, "Invalid input data argument type \"#{data.class}\""
	  end
	  if((data.is_a?(String) && data[0].ord != RADIUS::Packet::ACCESS_REJECT) ||
	     (data.is_a?(RADIUS::AuthPacket) && data.code != RADIUS::Packet::ACCESS_REJECT))
	    raise ArgumentError, "Not an ACCESS_REJECT packet"
	  end
	end

	if(request)
	  t = new(dict, RADIUS::Packet::ACCESS_REJECT, secret, data)
	  t.response_to(request)
	  t
	else
	  new(dict, RADIUS::Packet::ACCESS_REJECT, secret, data)
	end
      end
    end
  end

  # Provides an object-oriented interface to RADIUS accounting packets.
  # Can be instantiated either empty (no attributes), or an existing
  # RADIUS packet (received from a remote client or server, for example)
  # can be imported, provided it passes certain validity tests.
  class AcctPacket

    PORT = 1813

    def AcctPacket.dict
      @@dict
    end

    # Set up either a new, clean packet, or an already-processed packet.
    # 'dict' can be either a RADIUS::Dictionary object, or the filename
    # of a dictionary -- we will instantiate a new dictionary if the latter.
    # 'code' can be either RADIUS::Packet::ACCT_REQUEST (4),
    # or RADIUS::Packet::ACCT_RESP (5).
    # 'secret' is the shared secret between you and the remote client/server.
    # The optional 'data' argument, if present, should be a String containing
    # binary data to be imported as a new RADIUS Packet. The code bit in this
    # packet will override whatever you specify in 'code'.
    def initialize(dict, code, secret, data=nil)
      if(dict.is_a?(RADIUS::Dictionary))
	@@dict = dict
      else
	@@dict = RADIUS::Dictionary.new(dict)
      end

      AcctPacket.class_eval("include Packet")

      @secret = secret
      if(data)
	replace(data)
      else
	clear(code)
      end

      if(code == ACCT_REQUEST)
	instance_eval <<-EOD
	# Calculate the request authenticator. Unlike auth, this must
	# be recalc'd every time the packet changes
	def calc_authen
	  @packet[4..19] = Digest::MD5.digest(@packet[0..3] +
				      "\0" * 16 +
				      @packet[20...@packet.length] +
				      @secret)
	end

	def recalc_packet
	  super
	  calc_authen
	end
	EOD
      elsif(code == ACCT_RESP)
	@req_authen = nil
	instance_eval <<-EOD
	def calc_authen
	  if(! @req_authen)
	    return false
	  end
	  @packet[4..19] = Digest::MD5.digest(@packet[0..3] +
				      pack16(@req_authen) +
				      @packet[20...@packet.length] +
				      @secret)
	end
	def recalc_packet
	  super
	  calc_authen
	end
	EOD
      else
	raise RadiusProtocolError, "Wrong packet type for this class, or unsupported packet type"
      end

      recalc_packet
    end

    # Process and store the request authenticator, in one of many
    # possible forms. This information is used to calculate the
    # response authenticator, and should only be set in ACCT_RESP
    # packets.
    # IMPORTANT: If you just pass this method the RA, without the rest
    # of the packet, it won't be able to match up the identifier
    # field. This can cause strange problems.  You're best off passing
    # in either a binary String containing the entire request packet,
    # or a RADIUS::AcctPacket object.
    def response_to(ra)
      case ra
      when Integer
	@req_authen = ra
      when String
	if(valid_packet?(ra))
	  if(ra[0] != ACCT_REQUEST)
	    raise ArgumentError, "Not an ACCT_REQUEST packet"
	  end
	  @req_authen = unpack16(ra[4..19])
	  @packet[1] = ra[1]
	elsif(ra.length == 16)
	  @req_authen = unpack16(ra)
	else
	  raise ArgumentError, "I have no idea what that is"
	end
      when RADIUS::Packet
	if(ra.code != ACCT_REQUEST)
	  raise ArgumentError, "Not an ACCT_REQUEST packet"
	end
	@req_authen = ra.authen
	@packet[1] = ra.ident.chr
      end

      recalc_packet
    end

    class << self
      # Alternate constructor. Instantiates a new ACCT_REQUEST packet.
      # If the 'data' argument is present, it must be a valid ACCT_REQUEST
      # packet.
      def acct_request(dict, secret, data=nil)
	if(data)
	  if(! data.is_a?(String) && ! data.is_a?(RADIUS::AcctPacket))
	    raise ArgumentError, "Invalid input data argument type \"#{data.class}\""
	  end
	  if((data.is_a?(String) && data[0].ord != RADIUS::Packet::ACCT_REQUEST) ||
	     (data.is_a?(RADIUS::AcctPacket) && data.code != RADIUS::Packet::ACCT_REQUEST))
	    raise ArgumentError, "Not an ACCT_REQUEST packet"
	  end
	end

	new(dict, RADIUS::Packet::ACCT_REQUEST, secret, data)
      end

      # Alternate constructor. Instantiates a new ACCT_RESP packet.
      # If the 'data' argument is present, it must be a valid ACCT_RESP
      # packet.
      def acct_resp(dict, secret, data=nil, request=nil)
	if(data)
	  if(! data.is_a?(String) && ! data.is_a?(RADIUS::AcctPacket))
	    raise ArgumentError, "Invalid input data argument type \"#{data.class}\""
	  end
	  if((data.is_a?(String) && data[0].ord != RADIUS::Packet::ACCT_RESP) ||
	     (data.is_a?(RADIUS::AcctPacket) && data.code != RADIUS::Packet::ACCT_RESP))
	    raise ArgumentError, "Not an ACCT_RESP packet"
	  end
	end

	if(request)
	  t = new(dict, RADIUS::Packet::ACCT_RESP, secret, data)
	  # The new packet's response_to should throw its own exceptions, so no need to
	  # check the request.
	  t.response_to(request)
	  t
	else
	  new(dict, RADIUS::Packet::ACCT_RESP, secret, data)
	end
      end

      alias accounting_request acct_request
      alias accounting_resp acct_resp
    end
  end
end
