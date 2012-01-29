# Radiuslib for Ruby
# Dan Debertin <airboss@nodewarrior.org>


require "radius/dictionary"
require "radius/user"

module RADIUS

  # This class parses and provides r/w access to RADIUS "users" files.
  # The files used for testing are Cistron-format files, with the
  # proviso that cistron's "special" operators (:=, >=, etc.) are
  # not supported. 
  # This class works on the files that I have at my disposal.
  # If you're able to get it to break, please send me the error
  # output and the entry that caused the breakage. Also, any
  # "users" files that are idiosyncratic to a non-cistron 
  # RADIUS server would be welcome.
  class Usersfile
    # 'dict' is either a RADIUS::Dictionary object or the filename
    # of a dictionary. 'filename' is the name of the users-file
    # to parse. 
    def initialize(dict, filename="/etc/raddb/users")
      @filename = filename
      if(dict.kind_of?(RADIUS::Dictionary))
	@@dict = dict
      else
	@@dict = RADIUS::Dictionary.new(dict)
      end
      if(FileTest.readable?(@filename))
	@rusers = File.open(@filename, "r")
      end
      @users = {}
      @defaults = []
      if(@rusers)
	userparse(@rusers)
      end
    end

    private

    def userparse(file)
      # Parse a usersfile record and add the resulting
      # User object to either @users or @defaults.
      cur = nil
      file.each do |line|
	next if(line =~ /^#/)
	line.sub!(/#.*/, "")
	case line
	when /^([^\s]+)\s/
	  if(cur)
	    raise RadiusUtilError, "Nested user at line #{file.lineno}"
	  end
	  cur = RADIUS::User.new(@@dict, $1)
	  line.sub!(/^([^\s]+)\s+/, "")
	  line.scan(/([^\s]+)\s+([^\s]{1,2})\s+([^\",]?[^\s,]+[^\",]?|\"+(?:\\\"|[^\"])+\"+)[,\n]/).
	    each do |match|
	    if(@@dict[match[0]].datatype == 'integer' && match[2] =~ /^[[:digit:]]+$/)
	      cur[match[0]] = match[2].to_i
	    else
	      cur[match[0]] = match[2]
	    end
	  end
	when /^\s+([^\s]+)\s+([^\s]{1,2})\s+([^\",]?[^\s,]+[^\",]?|\"+(?:\\\"|[^\"])+\"+)(,)?\n/
	  if(! cur)
	    raise RadiusUtilError, "Reply item line with no current user at line #{file.lineno}"
	  end
	  match = [ $1, $2, $3, $4 ]
	  if(@@dict[match[0]].datatype == 'integer' && match[2] =~ /^[[:digit:]]+$/)
	    cur[match[0]] = match[2].to_i
	  else
	    cur[match[0]] = match[2]
	  end
	  if(match[3] != ',')
	    if(cur.username == 'DEFAULT')
	      @defaults << cur
	    else
	      @users[cur.username] = cur
	    end
	    cur = nil
	  end
	when /^\$include\s+([[:print:]]+)\n/i
	  userparse(File.open($1, "r"))
	when /^\s*$/
	  if(cur)
	    if(cur.username == 'DEFAULT')
	      @defaults << cur
	    else
	      @users[cur.username] = cur
	    end
	    cur = nil
	  end
	else
	  raise RadiusUtilError, "Format error on line #{file.lineno}"
	end
      end
      if(cur)
	if(cur.username == 'DEFAULT')
	  @defaults << cur
	else
	  @users[cur.username] = cur
	end
	cur = nil
      end
    end

    def dumpuser(rec)
      out = ''
      if(rec.comment)
	out += "\# #{rec.comment}\n"
      end
      out += "#{rec.username}\t"
      rec.each_check do |ck, cv|
	if(@@dict[ck].datatype == 'string')
	  cv = "\"#{cv}\""
	end
	out += "#{ck} = #{cv}, "
      end
      out.sub!(/, $/, "\n")
      rec.each_reply do |rk, rv|
	if(@@dict[rk].datatype == 'string')
	  rv = "\"#{rv}\""
	end
	out += "\t#{rk} = #{rv},\n"
      end
      out.sub!(/(.*),/m, "\\1\n")

      out
    end

    public

    # The usersfile is represented as a hash of RADIUS::User objects,
    # keyed on username. As there can be multiple DEFAULT entries,
    # they are not included in this representation. See the DEFAULT-
    # specific methods below.
    def [](user)
      @users[user]
    end

    # Access DEFAULT entries in an array-like manner.
    def default(defnum)
      @defaults[defnum]
    end

    # Add a user to the usersfile. The rvalue must be a valid
    # RADIUS::User object. Attempts to add a DEFAULT will raise
    # RadiusUtilError.
    def []=(idx, user)
      if(@users[idx])
	raise IndexError, "User #{idx} already exists"
      end
      if(! user.is_a?(RADIUS::User))
	raise TypeError, "Not a RADIUS::User object"
      end
      if(user.username == 'DEFAULT')
	raise RadiusUtilError, "DEFAULT users cannot be added with this method. Try #add_default instead."
      end
      @users[idx] = user 
    end

    # Add a DEFAULT entry to the array of DEFAULT users.
    # The rvalue must be a valid RADIUS::User object. Attempts
    # to add a non-DEFAULT user will raise RadiusUtilError.
    def add_default(user)
      if(! user.is_a?(RADIUS::User))
	raise TypeError, "Not a RADIUS::User object"
      end
      if(user.username != 'DEFAULT')
	raise RadiusUtilError, "Not a DEFAULT user"
      end
      @defaults << user
    end

    # Delete a user from the userlist.
    def delete(username)
      if(username == 'DEFAULT')
	raise RadiusUtilError, "DEFAULT users cannot be deleted with this method"
      end
      @users[user] = nil
    end

    # Delete a DEFAULT from the DEFAULT list. Because DEFAULTs don't
    # have names, a full RADIUS::User object with attributes that
    # match the desired DEFAULT must be supplied.
    def delete_default(user)
      if(! user.is_a?(RADIUS::User))
	raise TypeError, "Not a RADIUS::User object"
      end
      if(user.username != 'DEFAULT')
	raise RadiusUtilError, "Not a DEFAULT user"
      end

      each_default do |cur|
	if(cur == user)
	  @defaults.delete(cur)
	end
      end
    end

    # Iterate over the list of users. Yields the next RADIUS::User
    # object in the hash for every call.
    def each
      @users.each_value { |u| yield u }
    end

    # Iterate over the list of DEFAULT users. Yields the next
    # RADIUS::User object in the array for every call.
    def each_default
      @defaults.each { |d| yield d }
    end

    # Close the file, clear the list of users and DEFAULTs, reopen,
    # and re-parse.
    def reload
      @users.clear
      @defaults.clear
      @rusers.close if(@rusers)
      @rusers = File.open(@filename, "r")
      userparse(@rusers)
    end
      
    # Write the user hash and the DEFAULTs array out to disk.
    def update
      wusers = File.open(@filename, "w")
      each do |rec|
	wusers.print dumpuser(rec)
      end
      each_default do |rec|
	wusers.print dumpuser(rec)
      end
      wusers.close
      reload
    end

    def inspect
      "#<RADIUS::Usersfile file=#@filename, numusers=#{@users.size}, numdefaults=#{@defaults.size}>"
    end
  end
end
