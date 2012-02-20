require "radius/packet"
require "radius/user"
require "digest/md5"
require "socket"

module RADIUS

  # An interface to RADIUS authentication requests. This class
  # encapsulates a single RADIUS authentication transaction -- 
  # building the request, sending it to a server, parsing the
  # response and giving access to it.
  # As mentioned under RADIUS::Packet, the goal here as well
  # is to represent the transaction at all times in a valid form,
  # while preventing the user from having to do any "dirty work".
  # This means that User-Password/CHAP-Password attributes are
  # automatically encrypted, and re-encrypted when necessary.
  # Authentication mode (pap/chap) can be set explicitly (in which
  # case we will auto-convert any relevant attributes already present),
  # or it can be automatically detected based on the attributes given.
  class AuthRequest

    # Create a new request. 'dict' can be either a RADIUS::Dictionary
    # object, or the filename of a dictionary. 'host' is either a hostname
    # or IP address of the remote server. The port to use is chosen in the
    # following order:
    #
    # * port number specified with a colon (':') after the hostname or IP address
    # * result of a lookup in /etc/services for a UDP service called 'radius'
    # * The IANA-sanctioned port number, 1812, as a last resort.
    #
    # 'secret' is the shared secret between us and the server.
    # 'user' is an optional pre-initialized RADIUS::User object.
    # The check items from this object will be used to pre-populate the
    # request.
    def initialize(dict, host, secret, user=nil)
      @host = host
      @secret = secret
      @password = nil
      @auth_mode = nil

      if(dict.is_a?(RADIUS::Dictionary))
	@@dict = dict
      else
	@@dict = RADIUS::Dictionary.new(dict)
      end

      clear
      if(user)
	userinit(user)
      end
    end

    private

    def userinit(user)
      if(! user.is_a?(RADIUS::User))
	raise TypeError, "Not a RADIUS::User object"
      end

      @req_packet['User-Name'] = user.username
      user.each_check do |a, v|
	add(a, v)
      end
    end

    def add(i, v)
      if(! @@dict[i])
	      raise RadiusProtocolError, "Unknown attribute #{i}"
      end
      attrnum = @@dict[i].attrnum
      if(attrnum == 2)
      	@password = v
      	self.mode = 'pap'
      elsif(attrnum == 3 || attrnum == 60)
      	@password = v if(attrnum == 3)
      	self.mode = 'chap'
      end

      unless(attrnum == 2 || attrnum == 3 || attrnum == 60)
	      @req_packet[i] = v
      else 
      	# Recalc the password if we receive the challenge after it.
      	if(attrnum == 60 && @req_packet['CHAP-Password'])
      	  @req_packet.delete('CHAP-Password')
      	  @req_packet[i] = v
      	  @req_packet['CHAP-Password'] = @pwcalc.call(@password)
      	else
      	  @req_packet[i] = @pwcalc.call(v)
      	end
      end
    end

    def clear
      @req_packet = RADIUS::AuthPacket.access_request(@@dict, @secret)
      @cur = @req_packet
      @auth_mode = 'pap'
      @pwcalc = method(:calc_pap_password)
    end

    def calc_pap_password(p)
      # Pad the password to a 16-byte boundary
      while(p.length % 16 != 0)
        p += "\0"
      end

      # turn 32 bit authenticator number into a 4 byte string
      d = []
      4.times { |j| d.unshift((@req_packet.authen >> j * 32) & 0xffffffff) }
      curauth = d.pack("NNNN")
      presult = ''
      i=0
      # step through password 16 bytes at a time
      while (i < p.length)
        # we need to xor the current password segment with the md5 of the secret + authenticator
        # the authenticator will be come the prev password segment as we loop through the segments

        # if ruby supported xor on strings we could do:
        # curauth = p[i,i+15] ^ Digest::MD5.digest(@secret + curauth)

        # but instead we have to do the following
        # get the digest
        dig = Digest::MD5.digest(@secret + curauth)
        # step through each byte of the segment and xor with the digest
        0.upto(15) { |j| curauth[j] = [(p[i+j].ord ^ dig[j].ord)].pack("C") }

        # concat the result onto the encrypted password result
        presult += curauth

        # get ready to do next password segment
        i+=16
      end
      presult
    end

    def calc_chap_password(p)
      if(@req_packet['CHAP-Challenge'])
	chall = @req_packet['CHAP-Challenge'][0]
      else
	chall = @req_packet.authen_str
      end
      # I'm content to use random CHAP IDs ... any reason not to?
      id = [rand(255)].pack("C")
      id + Digest::MD5.digest(id + p + chall)
    end

    def vrfy_response_authen
      dig = Digest::MD5.digest(@resp_packet.to_s[0..3] + @req_packet.authen_str +
	      @resp_packet.to_s[20...@resp_packet.size] + @secret)
      dig == @resp_packet.authen_str
    end

    public

    # Set the authentication mode explicitly. The rvalue must be either
    # 'pap' or 'chap', case insensitive.
    # We delete all instances of the opposite mode's password attributes
    # when the mode changes.
    def mode=(m)
      m.downcase!
      case m
      when 'pap'
	@req_packet.delete('CHAP-Password')
	@req_packet.delete('CHAP-Challenge')
	@auth_mode = 'pap'
	@pwcalc = method(:calc_pap_password)
      when 'chap'
	@req_packet.delete('User-Password')
	@auth_mode = 'chap'
	@pwcalc = method(:calc_chap_password)
      else
	raise RadiusProtocolError, "Unknown auth mode #{m}"
      end
    end

    # Access the current packet's attributes. This will return attributes
    # from the request if we haven't called <em>send</em> yet. After that
    # point, it will access the response packet.
    def [](i)
      @cur[i]
    end

    # Access attributes in the request packet explicitly.
    def request(i)
      @req_packet[i]
    end

    # Access attributes in the response packet explicitly.
    def response(i)
      return nil if(! @resp_packet)
      @resp_packet[i]
    end

    # Delete an attribute from the current packet.
    def delete(a)
      @cur.delete(a)
    end

    # Delete a specific AV-pair from the current packet.
    def delete_pair(a, v)
      @cur.delete_pair(a, v)
    end

    # Return a hash of arrays representing the attributes and values
    # present in the current packet.
    def to_h
      @cur.to_h
    end

    # Return an array of the attributes present in the current packet.
    def attribs
      @cur.attribs
    end

    # Return an array of the values present in the current packet.
    def values
      @cur.values
    end

    # Iterate over the AV-pairs present in the current packet.
    def each
      @cur.each { |a, v| yield a, v }
    end

    # Send the request and await the response. The value of @cur
    # is changed at the end of this method; all of the getter methods
    # will access the response packet after this point.
    # Takes an optional 'count' parameter for the number of requests
    # to send, and a 'timeout' for the number of seconds to await
    # a response before re-sending.
    def send(count=5, timeout=5)
      if(@host =~ /:[0-9]+$/)
	host, port = *@host.scan(/^([^:]+):([0-9]+)$/)[0]
      elsif(s = getservbyname('radius', 'udp'))
	host = @host
	port = s.port
      else
	host = @host
	port = RADIUS::AuthPacket::PORT
      end
      Socket.do_not_reverse_lookup = true
      sock = UDPSocket.new
      sock.bind(0, 0)
      catch(:done) {
	count.times do
          begin
	    sock.send(@req_packet.to_s, 0, host, port)
          rescue
            # caught send exception like Errno::ENOBUFS, we should try again
            # up to the maximum count times.
            sleep(0.33)
            # print WARN message here maybe?
          end
	  throw :done if(select([sock], nil, nil, timeout))
	end
	sock.close
	return false
      }
      r = sock.recvfrom(RADIUS::Packet::PACKET_MAX)
      @serverinfo = r[1]
      @resp_packet = RADIUS::AuthPacket.new(@@dict, r[0][0].ord, @secret, r[0])
      @resp_packet.response_to(@req_packet)
      if(! vrfy_response_authen)
	raise RadiusProtocolError, "Received invalid response authenticator from server 2"
      end
      @cur = @resp_packet
      sock.close
      true
    end

    # The IP/UDP information received from the remote end. <em>nil</em> if
    # we haven't sent anything yet.
    attr_reader :serverinfo
    
    # The authentication mode
    attr_reader :auth_mode

    # <em>true</em> if the response packet was an ACCESS_ACCEPT packet.
    # <em>false</em> if the response packet was an ACCESS_REJECT packet.
    # <em>nil</em> otherwise.
    def success?
      return nil if(! @resp_packet)
      if(@resp_packet.code == RADIUS::Packet::ACCESS_ACCEPT)
	true
      elsif(@resp_packet.code == RADIUS::Packet::ACCESS_REJECT)
	false
      end
    end
    
    # Add an attribute/value pair to the request packet. 
    def []=(i, v)
      add(i, v)
    end
  end

  # An interface to RADIUS accounting requests. This class
  # encapsulates a single RADIUS accounting transaction.
  class AcctRequest
    # Create a new request. Arguments are the same as RADIUS::AuthRequest,
    # above, except for the following differences:
    # * the service looked up in /etc/services is radacct/udp.
    # * the default IANA-sanctioned port is 1813.
    # * if a RADIUS::User object is supplied as the last argument,
    #   the reply items, not the check items, are used to
    #   pre-initialize the request.
    def initialize(dict, host, secret, user=nil)
      @host = host
      @secret = secret
      
      if(dict.is_a?(RADIUS::Dictionary))
	@@dict = dict
      else
	@@dict = RADIUS::Dictionary.new(dict)
      end
      
      clear
      if(user)
	userinit(user)
      end
    end

    private

    def userinit(user)
      if(! user.is_a?(RADIUS::User))
	raise TypeError, "Not a RADIUS::User object"
      end

      @req_packet['User-Name'] = user.username
      user.each_reply do |a, v|
	@req_packet[a] = v
      end
    end

    def clear
      @req_packet = RADIUS::AcctPacket.acct_request(@@dict, @secret)
      @cur = @req_packet
    end

    def vrfy_response_authen
      dig = Digest::MD5.digest(@resp_packet.to_s[0..3] + @req_packet.authen_str +
	       @resp_packet.to_s[20...@resp_packet.size] + @secret)
      dig == @resp_packet.authen_str
    end

    public

    # Access the current packet's attributes. This will return attributes
    # from the request if we haven't called <em>send</em> yet. After that
    # point, it will access the response packet.
    def [](i)
      @cur[i]
    end

    # Access attributes in the request packet explicitly.
    def request(i)
      @req_packet[i]
    end

    # Access attributes in the response packet explicitly.
    def response(i)
      return nil if(! @resp_packet)
      @resp_packet[i]
    end

    # Delete an attribute from the current packet.
    def delete(a)
      @cur.delete(a)
    end

    # Delete a specific AV-pair from the current packet.
    def delete_pair(a, v)
      @cur.delete_pair(a, v)
    end

    # Return a hash of arrays representing the attributes and values
    # present in the current packet.
    def to_h
      @cur.to_h
    end

    # Return an array of the attributes present in the current packet.
    def attribs
      @cur.attribs
    end

    # Return an array of the values present in the current packet.
    def values
      @cur.values
    end

    # Iterate over the AV-pairs present in the current packet.
    def each
      @cur.each { |a, v| yield a, v }
    end

    # Send the request and await the response. The value of @cur
    # is changed at the end of this method; all of the getter methods
    # will access the response packet after this point.
    # Note that there is no notion of 'failure' or 'rejection' in
    # accounting -- the only valid response is ACCT_RESP.
    # Therefore there is no <em>success?</em> method.
    # Takes an optional 'count' parameter for the number of requests
    # to send, and a 'timeout' for the number of seconds to await
    # a response before re-sending.
    def send(count=5, timeout=5)
      if(@host =~ /:[0-9]+$/)
	host, port = *@host.scan(/^([^:]+):([0-9]+)$/)[0]
      elsif(s = getservbyname('radacct', 'udp'))
	host = @host
	port = s.port
      else
	host = @host
	port = RADIUS::AcctPacket::PORT
      end
      Socket.do_not_reverse_lookup = true
      sock = UDPSocket.new
      sock.bind(0, 0)
      catch(:done) {
	count.times do
          begin
	    sock.send(@req_packet.to_s, 0, host, port)
          rescue
            # caught send exception like Errno::ENOBUFS, we should try again
            # up to the maximum count times.
            sleep(0.33)
            # print WARN message here maybe?
          end
	  throw :done if(select([sock], nil, nil, timeout))
	end
	sock.close
	return false
      }
      r = sock.recvfrom(RADIUS::Packet::PACKET_MAX)
      @serverinfo = r[1]
      @resp_packet = RADIUS::AcctPacket.acct_resp(@@dict, @secret, r[0], @req_packet)
      if(! vrfy_response_authen)
	raise RadiusProtocolError, "Received invalid response authenticator from server 3"
      end
      @cur = @resp_packet
      sock.close
      true
    end

    # The IP/UDP information received from the remote end. <em>nil</em> if
    # we haven't sent anything yet.
    attr_reader :serverinfo

    # Dummy success method.
    def success?
      true
    end

    # Add an attribute/value pair to the request packet. 
    def []=(i, v)
      @req_packet[i] = v
    end

  end
end
