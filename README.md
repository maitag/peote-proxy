# peote-proxy
perl5 proxyserver that forwards tcp- or websocketprotocol packages to a tcp-server

This [TCP](https://en.wikipedia.org/wiki/Transmission_Control_Protocol) [Socket](https://upload.wikimedia.org/wikipedia/commons/thumb/3/3e/BLW_Pair_of_socks.jpg/320px-BLW_Pair_of_socks.jpg) Server together with [PeoteSocket](https://github.com/maitag/peote-socket) helps me  
to do crossplatform networkcoding with haxe.  


## Perl 5 Environment

On Linux everything should run out of the box (`apt install perl5 libpoe-perl && cpan Protocol::WebSocket`),
for Windows i recommend to use [strawberryperl](http://strawberryperl.com/).  

Adjust the peote-proxy.conf file and start it with `perl peote-proxy.pl`!

### Perlmodule dependencies

- [POE](http://search.cpan.org/~rcaputo/POE-1.367/lib/POE.pm) - ( http://poe.perl.org/ )
- [Protocol::WebSocket](http://search.cpan.org/~vti/Protocol-WebSocket/lib/Protocol/WebSocket.pm)  


## TODO:
- testing with different maxpayload of WebSocket.pm
- hardening (iptables)
- standalone packages (par)
