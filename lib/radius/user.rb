# Radiuslib for Ruby
# Dan Debertin <airboss@nodewarrior.org>

require "radius/dictionary"

module RADIUS

  # An abstract class representing a single user. This is used
  # as an idiosyncratic storage medium for the two ::Request
  # classes, as well as any that deal with users at the 
  # utility level (usersfile, for example).
  class User

    # Anything not in this array is a reply item. To prevent
    # confusing inconsistencies (Password/User-Password, etc.),
    # use only attribute numbers as they appear in the dictionary.
    CHECK_ITEMS = [ 
      2, 3, 4, 5, 30, 31, 32, 60, 61, 1030, 1031, 
      1040, 1041, 1000, 1003, 1004, 1005, 1006 ]

    # 'dict' can either be a RADIUS::Dictionary object, or
    # the filename of a dictionary. 'username' can be
    # nil only if 'pairs' contains the 'User-Name' attribute.
    def initialize(dict, username=nil, pairs=nil)
      if(! defined?(@@dict))
	if(dict.kind_of?(RADIUS::Dictionary))
	  @@dict = dict if(! defined?(@@dict))
	else
	  @@dict = RADIUS::Dictionary.new(dict)
	end
      end
      @username = username
      @check = {}
      @reply = {}
      if(pairs)
	pairs.each_key do |a|
	  if(a == 'User-Name')
	    @username = pairs[a][0].gsub!(/(?:([^\\])|^)\"/, '\1')
	    next
	  end
	  pairs[a].each { |v| pairadd(a, v) }
	end
      end
      if(! @username)
	raise ArgumentError, "No username given"
      end
    end

    attr_reader :username
    attr_accessor :comment
    
    private

    def pairadd(attr, val)
      # Eliminate unescaped quotes.
      if(val.is_a?(String))
	val.gsub!(/(?:([^\\])|^)\"/, '\1')
      end
      if(CHECK_ITEMS.index(@@dict[attr].attrnum))
	@check[attr] ||= []
	@check[attr] << val 
      else
	@reply[attr] ||= []
	@reply[attr] << val 
      end
    end

    def pairdel(attr, val=nil)
      if(CHECK_ITEMS.index(@@dict[attr].attrnum))
	return if(! @check[attr])
	if(val)
	  @check[attr].delete_if { |v| v == val }
	  @check[attr] = nil if(@check[attr].empty?)
	else
	  @check.delete(attr)
	end
      else
	return if(! @reply[attr])
	if(val)
	  @reply[attr].delete_if { |v| v == val }
	  @reply[attr] = nil if(@reply[attr].empty?)
	else
	  @reply.delete(attr)
	end
      end
    end

    def pairget(attr)
      return nil if(! @@dict[attr])
      if(CHECK_ITEMS.index(@@dict[attr].attrnum))
	return @check[attr]
      else
	return @reply[attr]
      end
    end

    def attrdel(attr)
      if(CHECK_ITEMS.index(@@dict[attr].attrnum))
	@check[attr] = nil
      else
	@reply[attr] = nil
      end
    end

    public

    # Add an AV-pair to the user.
    def []=(idx, val)
      val.gsub!(/(?:([^\\])\"|^\")/, '\1') if(val.kind_of?(String))
      if(! @@dict[idx])
	raise RadiusUtilError, "Unknown attribute #{idx}"
      end
      pairadd(idx, val)
    end

    # Delete either all instances of an attribute, or a particular
    # AV-pair from the user.
    def delete(attr, val=nil)
      pairdel(attr, val)
    end

    # Iterate over all pairs in the user.
    def each
      each_check { |c, v| yield c, v }
      each_reply { |c, v| yield c, v }
    end

    # Iterate over only the check items.
    def each_check
      @check.each do |ck, cv|
	cv.each do |cvv|
	  yield ck, cvv
	end
      end
    end

    # Iterate over only the reply items.
    def each_reply
      @reply.each do |rk, rv|
	rv.each do |rvv|
	  yield rk, rvv
	end
      end
    end

    # Iterate over each attribute-name in the user.
    def each_attr
      @check.each_key { |ck| yield ck }
      @reply.each_key { |rk| yield rk }
    end

    # Return an array of attributes present in the user. Duplicates
    # are suppressed.
    def attributes
      res = []
      each_attr { |a| res << a }

      res.uniq
    end

    # Return an array of values present in the user.
    def values
      res = []
      each_val { |v| res << v }

      res
    end

    # Iterate over the values present in the user.
    def each_val
      @check.each_value do |cv|
	cv.each { |cvv| yield cvv }
      end
      @reply.each_value do |rv|
	rv.each { |rvv| yield rvv }
      end
    end

    alias each_value each_val

    # Access AV-pairs in the user.
    def [](idx)
      pairget(idx)
    end

    # Return a hash of arrays containing the AV-pairs.
    def to_h
      phash = {}
      each do |a, v|
	phash[a] ||= []
	phash[a] << v
      end

      phash
    end

    # Compares attributes. We assume that the username is
    # different, otherwise this method would be useless.
    def ==(cmp)
      if(! cmp.kind_of?(RADIUS::User))
	return false
      end
      # obviously...
      return true if self.id == cmp.id
      cmp.each_attr do |cmpk|
	if(pairget(cmpk) != cmp[cmpk])
	  return false
	end
      end
      self.each_attr do |sk|
	if(cmp[sk] != pairget(sk))
	  return false
	end
      end
      
      true
    end

    # Handle the trivial case where we want to know if
    # two Users are exactly the same, including username.
    def cmp(cmp)
      return false if(self != cmp)
      return false if(@username != cmp.username)
      
      true
    end

    # Does this instance have attr as a check item?
    def check_item?(attr)
      return true if(@check[attr])
      false
    end

    # Does this instance have attr as a reply item?
    def reply_item?(attr)
      return true if(@reply[attr])
      false
    end

    # Is this attribute present in the user?
    def has_attr?(attr)
      return true if(reply_item?(attr) || check_item?(attr))
      false
    end

    # Is attr recognized by this class as a check item?
    # The class methods require attr to be a Struct::Raddict.
    def User.check_item?(attr)
      if(! defined?(@@dict))
	return nil
      end
      return true if(CHECK_ITEMS.index(@@dict[attr].attrnum))
      false
    end

    # Is attr recognized by this class as a reply item?
    # The class methods require attr to be a Struct::Raddict.
    def User.reply_item?(attr)
      if(! defined?(@@dict))
	return nil
      end
      return true if(! CHECK_ITEMS.index(@@dict[attr].attrnum))
      false
    end

    # Set the class-level dictionary. You need to set this
    # if you're going to use the #check_item? and #reply_item?
    # class methods.
    def User.dict=(dict)
      if(dict.kind_of?(RADIUS::Dictionary))
	@@dict = dict
      else
	@@dict = RADIUS::Dictionary.new(dict)
      end
    end      
    include Enumerable

  end # User
end # RADIUS
