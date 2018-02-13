#!/usr/bin/perl

# http://poe.perl.org/?POE_Cookbook/TCP_Servers

use warnings;
use strict;

# Include POE and POE::Component::Server::TCP.

use POE qw(Component::Server::TCP);

# Start a TCP server.  Client input will be logged to the console and
# echoed back to the client, one line at a time.

POE::Component::Server::TCP->new(
  Alias       => "echo_server",
  Port        => 7685,
  ClientInput => sub {
    my ($session, $heap, $input) = @_[SESSION, HEAP, ARG0];
    print "Session ", $session->ID(), " got input: $input\n";
    $heap->{client}->put($input);
  }
);

# Start the server.

$poe_kernel->run();
exit 0;