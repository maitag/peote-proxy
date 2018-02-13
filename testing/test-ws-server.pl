#!/usr/bin/perl

use warnings;
use strict;

use POE qw(Component::Server::TCP);

use Protocol::WebSocket::Handshake::Server;
use Protocol::WebSocket::Frame;

my $handshake = Protocol::WebSocket::Handshake::Server->new;
my $frame     = Protocol::WebSocket::Frame->new;

POE::Component::Server::TCP->new(
    Port         => 3211,
    ClientFilter => 'POE::Filter::Stream',
    ClientInput  => 
        sub
        {
            my $chunk = $_[ARG0];
            
            #print "Client Input:".$chunk."\n\n";

            if (!$handshake->is_done)
            {
                
                $handshake->parse($chunk);

                if ($handshake->is_done)
                {
                    $_[HEAP]{client}->put($handshake->to_string);
                }

                return;
            }

            $frame->append($chunk);

            #while (my $message = $frame->next)
            while (my $message = $frame->next_bytes)
            {
                # debug incomming bytes
                foreach my $c (unpack( 'C*', $message )) { print sprintf( "%lu ", $c ); }; print "\n";
                
                #$_[HEAP]{client}->put($frame->new($message)->to_bytes);
                $_[HEAP]{client}->put($frame->new(buffer => $message, type => 'binary')->to_bytes);
            }
        }
);

POE::Kernel->run;
