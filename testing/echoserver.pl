#!/usr/bin/perl

# http://poe.perl.org/?POE_Cookbook/TCP_Servers

use warnings;
use strict;

# Include POE and POE::Component::Server::TCP.

use POE qw(Component::Server::TCP Filter::Stream);

# Start a TCP server.  Client input will be logged to the console and
# echoed back to the client, one line at a time.

POE::Component::Server::TCP->new(
  #Alias       => "echo_server",
  Hostname => 'localhost',
  #Address => '127.0.0.1',
  Port        => 7680,
  ClientFilter => "POE::Filter::Stream",
  ClientInput => sub {
    my ($session, $heap, $input) = @_[SESSION, HEAP, ARG0];
    # print "Session ", $session->ID(), " got input: ".length($input)."\n";
    $heap->{client}->put($input);
  },
  Error => sub {
    my ($syscall_name, $err_num, $err_str) = @_[ARG0..ARG2];
    print "ERROR: ", $syscall_name, $err_num, $err_str;
  }
);

# Start the server.

$poe_kernel->run();
exit 0;