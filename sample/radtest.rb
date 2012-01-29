#!/usr/local/bin/ruby
# Radiuslib for Ruby
# Dan Debertin <airboss@nodewarrior.org>
#
# This is an example program demonstrating how to use the request classes
# in Radiuslib.
#

require "radius/request"
require "getoptlong"

def usage(err)
  print <<-EOF
  radtest.rb: send requests to a RADIUS server.
  Example: #$0 -c testuser testpass radiusserver MySeCrEt

  Syntax: #$0 [-cpov] [-d <dict>] [-f <filename>] [<username>] [<password>] <server[:port]> <secret>
  Options:

  -c, --chap		Use CHAP to authenticate.
  -p, --pap		Use PAP to authenticate (default).
  -o, --accounting	Send an accounting request, not authentication.
  -f, --file		Read attributes from <filename>. A '-' can be
			supplied to read attributes from STDIN.
  -d, --dict            The name of a dictionary (default: /etc/raddb/dictionary)
  -v, --verbose		Increase verbosity.
  -h, --help            This message.
  EOF
  exit err
end

options = GetoptLong.new(
			 [ "--chap",       "-c", GetoptLong::NO_ARGUMENT ],
			 [ "--pap",        "-p", GetoptLong::NO_ARGUMENT ],
			 [ "--accounting", "-o", GetoptLong::NO_ARGUMENT ],
			 [ "--file",       "-f", GetoptLong::REQUIRED_ARGUMENT ],
			 [ "--verbose",    "-v", GetoptLong::NO_ARGUMENT ],
			 [ "--dict",       "-d", GetoptLong::REQUIRED_ARGUMENT ],
			 [ "--help",       "-h", GetoptLong::NO_ARGUMENT ]
			 )

acct, username, infile, dictfile = nil
auth_mode = 'pap'

begin

  options.each do |opt, arg|
    case opt
    when '--chap'
      auth_mode = 'chap'
    when '--pap'
      auth_mode = 'pap'
    when '--accounting'
      acct = 1
    when '--file'
      if(arg == '-')
	infile = $stdin
      else
	infile = File.open(arg, "r")
      end
    when '--verbose'
      $VERBOSE = 1
    when '--dict'
      dictfile = arg
    when '--help'
      usage(0)
    else
      raise
    end
  end

  if(! acct)
    username = ARGV.shift or raise
    password = ARGV.shift or raise
  end    
  server = ARGV.shift or raise
  secret = ARGV.shift or raise
rescue
  usage(1)
end

debug = proc { |mes| puts mes if($VERBOSE) }

# Pre-initialize the dictionary. You can just pass the filename of
# the dictionary to your request and user objects, but it's slightly
# more efficient to have one dictionary object that is passed to
# everything that needs it.

dictfile ||= "/etc/raddb/dictionary"
debug.call("Initializing dictionary #{dictfile}")
$dict = RADIUS::Dictionary.new(dictfile)

if(infile)
  debug.call("Processing input")
  avs = {}
  infile.each do |line|
    f = line.split
    avs[f[0]] ||= []
    avs[f[0]] << f[2]
    debug.call("Read attribute #{f[0]} with value #{f[2]}")
  end
  debug.call("Initializing User object")
  user = RADIUS::User.new($dict, username, avs)
else
  user = nil
end

if(acct)
  debug.call("Initializing accounting request object")
  request = RADIUS::AcctRequest.new($dict, server, secret, user)
else
  debug.call("Initializing authentication request object")
  request = RADIUS::AuthRequest.new($dict, server, secret, user)
  request.mode = auth_mode
  if(auth_mode == 'pap')
    request['User-Password'] = password
  else
    request['CHAP-Password'] = password
  end
end
# We don't know if User-Name was one of the AVs in the file...
if(! request['User-Name'])
  request['User-Name'] = username
end

debug.call("Ok, Sending request")
puts "Sending request to #{server}...."
if(! request.send)
  puts "No response received from remote end"
  exit 1
end
puts "Reply recieved from #{request.serverinfo[3]}, port #{request.serverinfo[1]}"
if(request.success?)
  request.each { |k, v| puts "\t#{k} = #{v}" }
else
  puts "Access denied."
end
