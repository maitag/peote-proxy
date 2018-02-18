#!/usr/bin/perl -w
# Author, Date: Sylvio Sell, 2016
# License: GNU GENERAL PUBLIC LICENSE Version 3 (https://www.gnu.org/licenses/gpl-3.0.txt)


# litle perl script to help haxe cosmousers (to get "real" socket feeling inside coding the web.)
# look here -> http://github.com/maitag/peote-socket for that bridge-building-fun on other side

use Cwd;
use strict;
use File::Spec;
use IO::File;
use POSIX qw(WNOHANG setsid errno_h);
use Socket;
use POE qw( Wheel::ReadWrite Wheel::SocketFactory Filter::Stream );
use English '-no_match_vars';
use Data::Dumper;
use FindBin '$RealBin';

delete @ENV{qw(IFS CDPATH ENV BASH_ENV PATH)};	 # Make %ENV safer
#$ENV{PATH}='/bin:/sbin:/usr/bin:/usr/sbin';

my $pdir;

BEGIN {
  $pdir = $RealBin;
}

use constant PID_FILE => "$pdir/peoteproxy.pid";
use constant CONFIG_FILE => "$pdir/peoteproxy.conf";

use lib $pdir;
use Protocol::WebSocket::Stateful;
use Protocol::WebSocket::Message;
use Protocol::WebSocket::Handshake::Server;
use Protocol::WebSocket::Frame;


chdir("$pdir");
umask(0);

check_args_();

# zuerst default werte setzen
my $config = {
	'address'=>'localhost',
	'port'=>7680,

	'allowed_forwards'=>'localhost:23', # comma separated list of allowed forward adresses

	'flash_policy_domain'=>'localhost',
	'flash_policy_port'=>23,

	'max_connections_per_ip'=>3,

	'logging'=>'on',
	'error_logging'=>'on',
	'access_logging'=>'on',

	'logfile'=>'', #'peoteproxy.log',
	'error_logfile'=>'', #'peoteproxy_error.log',
	'access_logfile'=>'', #'peoteproxy_access.log',
	
	'user'=>'',
	'daemon'=>'off',

	'debug'=>0
};
# Aufbau der Config und moegliche Werte
my $config_struct = {
	'address'=>'(DOMAIN|IP)',
	'port'=>'(NUMBER)',
	'allowed_forwards'=>'(ADRESSES)', # comma separated list of allowed forward adresses
	'flash_policy_domain'=>'(DOMAIN|IP)',
	'flash_policy_port'=>'(NUMBER)',
	'max_connections_per_ip'=>'(NUMBER)',
	'logging'=>['on','off'],
	'error_logging'=>['on','off'],
	'access_logging'=>['on','off'],
	'logfile'=>'(STRING)',
	'error_logfile'=>'(STRING)',
	'access_logfile'=>'(STRING)',
	'user'=>'(STRING)',
	'daemon'=>['on','off']
};

# config einlesen
$config = read_config_(CONFIG_FILE);

if ($config->{'user'} ne '' && $^O !~ /win/i)
{
	# if process started with root-rights, here is username to let run onto (u only need to start as root for vip ports < .?.)
	print "euid=".$EUID."\n";
	print "uid=".$UID."\n";
	print "egid=".$EGID."\n\n";

	$EGID = getpwnam($config->{'user'})." ".getpwnam($config->{'user'});
	$EUID = getpwnam($config->{'user'});

	print "neue euid=".$EUID."\n";
	print "neue uid=".$UID."\n";
	print "neue egid=".$EGID."\n\n";
}

if ($config->{'error_logging'} eq 'on')
{
	open(STDERR,">>".$pdir.'/'.$config->{'error_logfile'});
}
else
{
	open(STDERR,">/dev/null");
}

my $ipcount = {}; # max. numbers of connections per ip



my $pid;
if ($config->{'daemon'} eq 'on' && $^O !~ /win/i)
{
	my $quit=0;
	$SIG{CHLD} = sub {while (waitpid(-1,WNOHANG)>0) {} };
	$SIG{TERM} = $SIG{INT} = sub {$quit=1};


	# daemon starten und pid anlegen
	my $fh = open_pid_file(PID_FILE);
	$pid = bekomme_daemon();
	print $fh $pid;
	close $fh;

	print "Server with pid $pid started!\n";
	print "To stop Server use \'$0 stop\' (or \'$0 restart\')\n\n";

	open(STDIN,"</dev/null");
	open(STDOUT,">/dev/null");

	log_("--------------- daemon started ------------------\n");

	server_create( $config->{'address'}, $config->{'port'} );
	$poe_kernel->run_one_timeslice() while not $quit;
	${$poe_kernel->[POE::Kernel::KR_RUN]} |= POE::Kernel::KR_RUN_CALLED; # damit keine errormsg wegen run-flag 


	log_("--------------- daemon stopped ------------------\n\n");
}
else
{
	log_("--------------- started ------------------\n");
	server_create( $config->{'address'}, $config->{'port'} );
	POE::Kernel->run();
}

exit(0);



######################################################################################
######################################################################################
######################################################################################
sub server_create #fold00
{
	my ( $local_address, $local_port ) = @_;

	POE::Session->create(
		inline_states => {
			_start         => \&server_start,
			_stop          => \&server_stop,
			accept_success => \&server_accept_success,
			accept_failure => \&server_accept_failure,
		},
		#		  ARG0,			   ARG1,		ARG2,			 ARG3
		args => [ $local_address, $local_port ]
	);
}

######################################################################################

sub server_start #fold00
{
	my ( $heap, $local_addr, $local_port ) = @_[ HEAP, ARG0, ARG1, ARG2, ARG3 ];

	log_("+ Redirecting $local_addr:$local_port\n");
	
	$heap->{local_addr}  = $local_addr;
	$heap->{local_port}  = $local_port;
	
	# originale (root) user id setzen (wenn als root gestartet)
	my $tmpeui;
	if ($config->{'user'} ne '')
	{
		my $tmpeui = $EUID;
		$EUID = $UID;
	}
	
	$heap->{server_wheel} = POE::Wheel::SocketFactory->new(
		BindAddress	 => $local_addr,  # bind to this address
		BindPort	 => $local_port,  # and bind to this port
		Reuse		 => 'yes',        # reuse immediately
		SuccessEvent => 'accept_success', # generate this event on connection
		FailureEvent => 'accept_failure', # generate this event on error
	);
	
	# semmi: euid zuruecksetzen (auf normalen user)
	if ($config->{'user'} ne '')
	{
		$EUID = $tmpeui;
	}
}

######################################################################################

sub server_stop	 #fold00
{
	my $heap = $_[HEAP];
	log_("- Redirection from $heap->{local_addr}:$heap->{local_port} stopped.\n");
}

######################################################################################

sub server_accept_success  #fold00
{
	my ( $heap, $socket, $peer_host, $peer_port ) = @_[ HEAP, ARG0, ARG1, ARG2 ];
	
	my $anz_connections_per_ip = 0;
	$peer_host = inet_ntoa($peer_host);
	$ipcount->{$peer_port} = $peer_host; # stores number of connections from one IP
	foreach my $key (keys %{$ipcount}) { $anz_connections_per_ip++ if ($ipcount->{$key} eq $peer_host); }
	
	if ($anz_connections_per_ip <= $config->{'max_connections_per_ip'})
	{
		&forwarder_create( $socket, $peer_host, $peer_port);
	}
	else
	{	log_("    Connection by $peer_host closed ($config->{'max_connections_per_ip'} allowed) \n",'ACCESS');
		delete($ipcount->{$peer_port});
	}
}

######################################################################################

sub server_accept_failure  #fold00
{
	my ( $heap, $operation, $errnum, $errstr ) = @_[ HEAP, ARG0, ARG1, ARG2 ];
	log_("! Redirection from $heap->{local_addr}:$heap->{local_port}".
	     " encountered $operation error $errnum: $errstr\n",'ERROR');
	delete $heap->{server_wheel} if $errnum == ENFILE or $errnum == EMFILE;
}

######################################################################################

sub forwarder_create #fold00
{
	my ( $handle, $peer_host, $peer_port ) = @_;

	POE::Session->create(
		inline_states => {
			_start       => \&forwarder_start,
			_stop        => \&forwarder_stop,
			
			client_handshake   => \&forwarder_client_handshake   ,# check Clients socket bridge
			client_redirect    => \&forwarder_client_redirect,    # Client sent something
			client_redirect_ws => \&forwarder_client_redirect_ws, # Client sent something over websockets
			
			client_check_login_timeout => \&client_check_login_timeout, # timeout after login

			server_connect     => \&forwarder_server_connect,     # Connected to server.
			server_redirect    => \&forwarder_server_redirect,    # Server sent something.
			server_redirect_ws => \&forwarder_server_redirect_ws, # Server sent something over websockets
			
			server_error   => \&forwarder_server_error,  # Error on server socket.
			client_error   => \&forwarder_client_error,  # Error on client socket.
		},
		#         ARG0,	   ARG1,       ARG2,       ARG3,         ARG4
		args => [ $handle, $peer_host, $peer_port ]
	);
}

######################################################################################

sub forwarder_start { #fold00
	my ( $heap, $session, $kernel, $socket, $peer_host, $peer_port )
	    = @_[ HEAP, SESSION, KERNEL, ARG0, ARG1, ARG2, ARG3, ARG4 ];

	$heap->{log}         = $session->ID;
	$heap->{peer_host}   = $peer_host;
	$heap->{peer_port}   = $peer_port;
	
	log_("[$heap->{log}] Accepted connection from $peer_host:$peer_port\n",'ACCESS');
	
	$heap->{state} = 'handshake';
	$heap->{pending} = '';
	$heap->{pending_ws} = '';
	$heap->{is_websocket} = 0;
	
	$heap->{wheel_client} = POE::Wheel::ReadWrite->new(
		Handle	   => $socket,
		Driver	   => POE::Driver::SysRW->new,
		Filter	   => POE::Filter::Stream->new,
		InputEvent => 'client_handshake',
		ErrorEvent => 'client_error',
	);
	
	# timeout
	$kernel->delay( client_check_login_timeout => 5 );
}


######################################################################################

sub forwarder_client_handshake { #fold00
	#my ( $heap, $input ) = @_[ HEAP, ARG0 ];
	my ( $kernel, $session, $heap, $input ) = @_[ KERNEL, SESSION, HEAP, ARG0 ];	
	
	$heap->{pending} .= $input;
	
	if ( $heap->{state} eq 'handshake' )
	{
		# check first incomming byte to see whats may going on ;)
		if ($input =~ /^</)
		{
			$config->{debug} && print "waiting for full flash policy request\n";
			$heap->{state} = 'handshake-flash';
		}
		elsif ($input =~ /^G/)
		{
			$config->{debug} && print "waiting for full websocket handshake\n";
			$heap->{ws_handshake} = Protocol::WebSocket::Handshake::Server->new;
			$heap->{ws_frame}     = Protocol::WebSocket::Frame->new(type => 'binary');
			$heap->{state} = 'handshake-websocket';
		}
		else
		{
			$config->{debug} && print "no handshake\n";
			$heap->{state} = 'wait4ip';
		}
	}
	
	##########################################
	
	if ( $heap->{state} eq 'handshake-flash' )
	{
		if ($heap->{pending} =~ s/^(<policy-file-request\/>\0)//  )
		{
			my $policy = '<?xml version="1.0"?>';
			$policy .= '<!DOCTYPE cross-domain-policy SYSTEM "/xml/dtds/cross-domain-policy.dtd">';
			$policy .= '<cross-domain-policy>';
			$policy .= '<site-control permitted-cross-domain-policies="master-only"/>';
			$policy .= '<allow-access-from domain="'.$config->{'flash_policy_domain'}.'" to-ports="'.$config->{'flash_policy_port'}.'" />';
			$policy .= '</cross-domain-policy>';
			$policy .= pack("b",0);
			log_("[$heap->{log}] Client $heap->{peer_host}:$heap->{peer_port} gets flash policy\n",'ACCESS');
			exists ( $heap->{wheel_client} ) and $heap->{wheel_client}->put($policy);
			$heap->{state} = 'wait4ip';
		}
	}
	elsif ( $heap->{state} eq 'handshake-websocket' )
	{
		$heap->{ws_handshake}->parse($heap->{pending});
		$config->{debug} && print "pending after parse out for websocket: '".$heap->{pending}."'\n";
		
		if ($heap->{ws_handshake}->is_done)
		{
			$heap->{is_websocket} = 1;
			exists ( $heap->{wheel_client} ) and $heap->{wheel_client}->put($heap->{ws_handshake}->to_string);
			$heap->{state} = 'wait4ip';
		}

	}
	
	##########################################
	my $wanna_adress;
	my $wanna_port;   
	
	if ( $heap->{state} eq 'wait4ip' )
	{
		#my $bytesCSL = ''; foreach my $c (unpack( 'C*', $heap->{pending} )) { $bytesCSL .= sprintf( "%lu", $c )." "; }
		#print "waiting for ip >$bytesCSL\n";
		
		if ($heap->{is_websocket})
		{
			$heap->{ws_frame}->append($heap->{pending});
			while (my $message = $heap->{ws_frame}->next_bytes)
			{
				$heap->{pending_ws}.=$message;
			}
			
			if (!defined($heap->{'ip_length'}) && length($heap->{pending_ws})>=2) {
				($heap->{'ip_length'}, $heap->{pending_ws}) = unpack("S1 a*" ,$heap->{pending_ws});
				if ($heap->{'ip_length'}<3 || $heap->{'ip_length'}>100) {delete $heap->{wheel_client};return;}
			}						
			if (defined($heap->{'ip_length'}) && length($heap->{pending_ws})>=2+$heap->{'ip_length'})
			{
				($wanna_adress, $heap->{pending_ws}) = unpack("a".$heap->{'ip_length'}." a*", $heap->{pending_ws}); # domain/ip string abziehen
				($wanna_port,   $heap->{pending_ws}) = unpack("S1 a*", $heap->{pending_ws}); # uint16 fuer port abziehen
				$heap->{state} = 'forward';
			}
		}
		else
		{
			if (!defined($heap->{'ip_length'}) && length($heap->{pending})>=2) {
				($heap->{'ip_length'}, $heap->{pending}) = unpack("S1 a*" ,$heap->{pending});
				if ($heap->{'ip_length'}<3 || $heap->{'ip_length'}>100) {delete $heap->{wheel_client};return;}
			}
			if (defined($heap->{'ip_length'}) && length($heap->{pending})>=2+$heap->{'ip_length'})
			{
				($wanna_adress, $heap->{pending}) = unpack("a".$heap->{'ip_length'}." a*", $heap->{pending}); # domain/ip string abziehen
				($wanna_port,   $heap->{pending}) = unpack("S1 a*", $heap->{pending}); # uint16 fuer port abziehen
				$heap->{state} = 'forward';
			}
		}
	}
	
	##########################################
	
	if ( $heap->{state} eq 'forward' )
	{
		delete $heap->{'ip_length'};
		
		if ($wanna_port<1 || !defined($config->{'allowed_forwards'}->{$wanna_adress.':'.$wanna_port}) )
		{
			log_("[$heap->{log}] Server adress send by client not in allowed\n",'ACCESS'); # TODO: block IP
			delete $heap->{wheel_client};
			return;
		}
		
		$heap->{state} = 'connecting';
		$heap->{remote_addr} = $wanna_adress.":".$wanna_port;
		# start connection to forward server
		$heap->{wheel_server} = POE::Wheel::SocketFactory->new(
			RemoteAddress => $wanna_adress,
			RemotePort    => $wanna_port,
			SuccessEvent  => 'server_connect',
			FailureEvent  => 'server_error',
		);
	}
}

######################################################################################

sub forwarder_client_redirect { #fold00
	my ( $heap, $input ) = @_[ HEAP, ARG0 ];
	#print "forwarder_client_redirect "; my $bytesCSL = ''; foreach my $c (unpack( 'C*', $input )) { $bytesCSL .= sprintf( "%lu", $c )." "; } print ">$bytesCSL\n";
	exists ( $heap->{wheel_server} ) and $heap->{wheel_server}->put($input);
}

######################################################################################

sub forwarder_client_redirect_ws { #fold00
	my ( $heap, $input ) = @_[ HEAP, ARG0 ];
	
	$heap->{ws_frame}->append($input);
	my $again=1;
	while ($again)
	{
		my $message = $heap->{ws_frame}->next_bytes;
		if (defined($message))
		{	
			if (length($message) > 0)
			{
				#print "forwarder_client_redirect_ws "; my $bytesCSL = ''; foreach my $c (unpack( 'C*', $message )) { $bytesCSL .= sprintf( "%lu", $c )." "; } print ">$bytesCSL\n";
				#print "forwarder_client_redirect_ws ".length($message)."\n";
				exists ( $heap->{wheel_server} ) and $heap->{wheel_server}->put($message);
			}
		}
		else {$again = 0;}
	}
}

######################################################################################

sub forwarder_server_connect { #fold00
	my ( $kernel, $session, $heap, $socket ) = @_[ KERNEL, SESSION, HEAP, ARG0 ];

	$heap->{state} = 'connected';
	
	if ($heap->{is_websocket})
	{
		$heap->{ws_frame}->append($heap->{pending});
		while (my $message = $heap->{ws_frame}->next_bytes)
		{
			$heap->{pending_ws}.=$message;
		}
	}
	
	if (exists( $heap->{wheel_client} ))
	{
		$heap->{wheel_server} = POE::Wheel::ReadWrite->new(
			Handle	   => $socket,
			Driver	   => POE::Driver::SysRW->new,
			Filter	   => POE::Filter::Stream->new,
			InputEvent => ($heap->{is_websocket}) ? 'server_redirect_ws' : 'server_redirect',
			ErrorEvent => 'server_error',
		);
		
		if ($heap->{is_websocket})
		{
			#my $bytesCSL = ''; foreach my $c (unpack( 'C*', $heap->{pending_ws} )) { $bytesCSL .= sprintf( "%lu", $c )." "; }
			#print " --- connecting - pend: '$bytesCSL'\n";
	
			#if ($heap->{pending_ws} ne '') { $kernel->post( $session, 'client_redirect_ws', $heap->{pending_ws} ); }
			if ($heap->{pending_ws} ne '') { exists ( $heap->{wheel_server} ) and $heap->{wheel_server}->put($heap->{pending_ws});}
			$heap->{wheel_client}->event(InputEvent => 'client_redirect_ws');
			#print "redirect to websocket\n---------------------------\n";
			delete $heap->{pending_ws};
		}
		else
		{
			#my $bytesCSL = ''; foreach my $c (unpack( 'C*', $heap->{pending} )) { $bytesCSL .= sprintf( "%lu", $c )." "; }
			#print " --- connecting - pend: '$bytesCSL'\n";
	
			#if ($heap->{pending} ne '') { $kernel->post( $session, 'client_redirect', $heap->{pending} ); }
			if ($heap->{pending} ne '') { exists ( $heap->{wheel_server} ) and $heap->{wheel_server}->put($heap->{pending});}
			$heap->{wheel_client}->event(InputEvent => 'client_redirect');
			#print "redirect pure\n--------------------------\n";
		}
		
		delete $heap->{pending};
		
		my ( $local_port, $local_addr ) = unpack_sockaddr_in( getsockname($socket) );
		$local_addr = inet_ntoa($local_addr);
		$heap->{client_addr} = "$local_addr:$local_port";
		
		log_("[$heap->{log}] Start forwarding $heap->{client_addr} to $heap->{remote_addr} ".
		     (($heap->{is_websocket}) ? '(websocket)' : '')."\n");
		$heap->{state} = 'established';
		$kernel->delay( client_check_login_timeout => undef );
	}
	
}
######################################################################################

sub forwarder_stop { #fold00
	my $heap = $_[HEAP];
	delete($ipcount->{$heap->{peer_port}});
	
	if ($heap->{state} eq 'established')
	{
		log_("[$heap->{log}] Stop  forwarding $heap->{client_addr} to $heap->{remote_addr}\n");
	}
	else
	{
		log_("[$heap->{log}] Closing redirection session from $heap->{peer_host}:$heap->{peer_port}\n",'ACCESS');
	}
}

######################################################################################

sub forwarder_server_redirect { #fold00
	my ( $heap, $input ) = @_[ HEAP, ARG0 ];
	#print "-forwarder_server_redirect "; my $bytesCSL = ''; foreach my $c (unpack( 'C*', $input )) { $bytesCSL .= sprintf( "%lu", $c )." "; } print ">$bytesCSL\n";
	#print "-forwarder_server_redirect ". length $input ."\n";
	exists( $heap->{wheel_client} ) and $heap->{wheel_client}->put($input);
}

######################################################################################

sub forwarder_server_redirect_ws { #fold00
	my ( $heap, $input ) = @_[ HEAP, ARG0 ];
	#print "-forwarder_server_redirect_ws "; my $bytesCSL = ''; foreach my $c (unpack( 'C*', $input )) { $bytesCSL .= sprintf( "%lu", $c )." "; } print ">$bytesCSL\n";
	#print "-forwarder_server_redirect_ws ".length($input)."\n";
	exists( $heap->{wheel_client} ) and $heap->{wheel_client}->put( Protocol::WebSocket::Frame->new(buffer => $input, type => 'binary')->to_bytes );
}

######################################################################################

sub forwarder_client_error { #fold00
	my ( $kernel, $heap, $operation, $errnum, $errstr ) =
	  @_[ KERNEL, HEAP, ARG0, ARG1, ARG2 ];

	defined($heap->{client_addr}) or $heap->{client_addr} = "$heap->{peer_host}:$heap->{peer_port}";
	if ($errnum) {
		log_("[$heap->{log}] Client $heap->{client_addr} encountered $operation error $errnum: $errstr\n",'ERROR');
	}
	else {
		log_("[$heap->{log}] Client $heap->{client_addr} close connection.\n",'ACCESS');
	}
	
	$kernel->delay( client_check_login_timeout => undef );
	delete $heap->{wheel_client};
	delete $heap->{wheel_server};
}

######################################################################################

sub forwarder_server_error { #fold00
	my ( $kernel, $heap, $operation, $errnum, $errstr ) = @_[ KERNEL, HEAP, ARG0, ARG1, ARG2 ];
	
	defined($heap->{client_addr}) or $heap->{client_addr} = "$heap->{peer_host}:$heap->{peer_port}";
	if ($errnum) {
		log_("[$heap->{log}] Server $heap->{remote_addr} to $heap->{client_addr} encountered $operation error $errnum: $errstr\n",'ERROR');
	}
	else {
		log_("[$heap->{log}] Server $heap->{remote_addr} close connection to $heap->{client_addr}.\n",'ACCESS');
	}
	
	$kernel->delay( client_check_login_timeout => undef );
	delete $heap->{wheel_client};
	delete $heap->{wheel_server};
}

######################################################################################
sub client_check_login_timeout {
	my $heap = $_[HEAP];    

	defined($heap->{client_addr}) or $heap->{client_addr} = "$heap->{peer_host}:$heap->{peer_port}";
	log_("[$heap->{log}] Login-Timeout for $heap->{client_addr}\n");

	delete( $ipcount->{ $heap->{peer_port} } );
	delete $heap->{wheel_client};
}

######################################################################################

sub check_args_ #fold00
{
	if (@ARGV)
	{
		if ($ARGV[0] =~ m/^stop|restart$/i)
		{
			if (-e PID_FILE)
			{
				my $fh = IO::File->new(PID_FILE) || die "Can\'t read from PID-File!\n";
				my $pid = <$fh>; # pid lesen
				close $fh;
				unless (-w PID_FILE && unlink PID_FILE) {die "Can\'t delete PID-File (".PID_FILE.")!\n";}
				$pid =~ /(.*)/;
				my $pid_untainted = $1;
				unless (kill INT => $pid_untainted) {die "Can\'t kill Server-Process with pid $pid_untainted !\n";}
				print "Server with Process-ID $pid was shutting down succesful!\n";
				if ($ARGV[0] =~ m/stop/i)
				{
					die "Good bye.\n";
				}
				print "Restarting Server...\n";
				sleep(1);
			}
			else
			{
				die "Server normally not running if no PID-File is available!\n(".PID_FILE." does not exist)\nTry \"ps xa\" and kill server-process if it\'s still running!\n\n";
			}
		}
	}

}

######################################################################################

sub read_config_ #fold00
{
	my $fn = shift;
	if (open(FOU, "<".$fn))
	{
		while (<FOU>)
		{
			chomp;				# linebreak
			s/#.*//;			# comments
			s/^\s+//;			# spaces at beginning
			s/\s+$//;			# leerzeichen am ende
			next unless length;		# any more
			my ($var, $wert) = split(/\s*=\s*/, $_, 2);
			$var = lc($var);
			$wert = lc($wert);
			if (defined($config_struct->{$var}))
			{	
				if (ref($config_struct->{$var}) eq 'ARRAY')
				{
					if (grep {$_ eq $wert} @{$config_struct->{$var}})
					{
						$wert =~ /(.*)/;
						$config->{$var} = $1; # untainting;
					}
					else
					{
						die "Error in config, possible values for \'$var\' = ".join(' | ',@{$config_struct->{$var}})."\n";
					}
				}
				else
				{
					if ($config_struct->{$var} eq '(NUMBER)')
					{
						if ($wert =~ /(\d+)/)
						{
							$config->{$var} = $1; # untainting;
						}
						else
						{
							die "Error in config, value for \'$var\' is not a number!\n";
						}
						
					}
					if ($config_struct->{$var} eq '(STRING)')
					{
						if ($wert =~ /['"]*([^'"]*)['"]*/)
						{
							$config->{$var} = $1; # untainting;
						}
						else
						{
							die "Error in config, value for \'$var\' contains no string!\n";
						}
						
					}
					elsif ($config_struct->{$var} eq '(IP)')
					{
						if ($wert =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/)
						{
							$config->{$var} = $1; # untainting;
						}
						else
						{
							die "Error in config, value for \'$var\' is not an IP Adress!\n";
						}
					}
					elsif ($config_struct->{$var} eq '(DOMAIN|IP)')
					{
						if ($wert =~ /^\s*([\w\-\.]+)\s*$/) # not matching 100% domains or ip
						{
							$config->{$var} = $1; # untainting;
						}
						else
						{
							die "Error in config, value for \'$var\' (no valid domain or ip)\n";
						}
					}
					elsif ($config_struct->{$var} eq '(ADRESSES)')
					{
						my @adresses = split(/\s*,\s*/, $wert);
						my @no_valid = grep { $_ !~ /^[\w\-\.]+:\d+$/ }  @adresses;
						
						if (@no_valid) {
							die "Error in config for \'$var\' -> no valid domain:port or ip:port -> \'".join( ', ', @no_valid )."\'\n";							
						}
						else {
							$config->{$var} = {map { $_ => 1 } @adresses};
							print "Allowed servers to forward: ".join( ', ', @adresses )."\n\n";
						}
					}
				}
			}
			else
			{
				die "Error in config, unknow param: \'$var\'\n";
			}
		}
	}
	return ($config);
}

######################################################################################

sub log_ #fold00
{
	my ($msg, $typ) = @_;
	
	my $logfile = $config->{'logfile'};
	
	if ($config->{'logging'} eq 'on')
	{
		defined($typ) or $typ = ' ';
		if ($typ eq 'ACCESS')
		{
			$config->{'access_logging'} eq 'on' or return;
			$typ = 'A';
			if ($config->{'access_logfile'}) {
				$logfile = $config->{'access_logfile'};
				$typ = '';
			}
		}
		elsif ($typ eq 'ERROR')
		{
			$config->{'error_logging'} eq 'on' or return;
			$typ = 'E';
			if ($config->{'error_logfile'}) {
				$logfile = $config->{'error_logfile'};
				$typ = '';
			}
		}			
		
		if ($logfile ne '')
		{
			if (open(FOU, ">>".$pdir.'/'.$logfile))
			{
				print FOU get_time()." $typ ".$msg;
				close FOU;
			}
			else
			{
				die "cant open logfile $logfile";
			}
		}
		else
		{
			print get_time()." $typ ".$msg;
		}
		
	}
	
	
}
#############################################################################

sub get_time #fold00
{
	my $newmin=0;my $newh=0;my $newtag=0;my $newmonat=0;my $newjahr=0;
	($newmin,$newh,$newtag,$newmonat,$newjahr) = (localtime(time()))[1,2,3,4,5];
	$newmonat++;$newjahr += 1900;
	$newmin = '0'.$newmin if ($newmin < 10);
	$newh = '0'.$newh if ($newh < 10);
	my $dasdatum = $newh.':'.$newmin.' '.$newjahr.'/'.$newmonat.'/'.$newtag;
	return($dasdatum);
}


######################################################################################

sub open_pid_file #fold00
{
	my $f = shift;
	if (-e $f) # pid existiert schon
	{
		my $fh = IO::File->new($f) || die "Can\'t read from PID-File!\n";
		my $pid = <$fh>; # pid lesen
		close $fh;
		$pid =~ /(.*)/;
		my $pid_untainted = $1;
		# if (kill 0 => $pid) { print "Server already runs with PID $pid !\n";die "Server already runs with PID $pid !\n";}
		if (kill 0 => $pid_untainted) { die "Server already runs with PID $pid !\n";}
		print "Please remove old PID-File manually because process with pid $pid doesn\'t exists!\n";
		unless (-w $f && unlink $f) {die "Can\`t delete PID-File $f !\n";}
	}
	return (IO::File->new($f,O_WRONLY|O_CREAT|O_EXCL,0644) or die "Cant create $f !\n");
}

######################################################################################

sub bekomme_daemon #fold00
{
	my $rc;
	unless (defined ($rc = fork )) {print "Fork isn\'t possible!\n"; die "Fork isn\'t possible!\n";}
	# parent abbruch
	exit(0) if $rc;
	setsid(); # hauptprozess werden
	return $$;
}

######################################################################################

END { #fold00
	if (defined($pid))
	{
		if ($$ == $pid && (-e PID_FILE))
		{
			if (-w PID_FILE)
			{
				unless (unlink PID_FILE)
				{
					die "Can\`t delete PID-File ",PID_FILE,";!\n";
				}
			}
			else
			{
				die "Can\`t write Pid-file",PID_FILE,"!\n";
			}
		}
	}
}

