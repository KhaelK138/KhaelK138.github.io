#!/usr/bin/perl
use strict;
use warnings;

print "Content-type: text/html\n\n";
print "<html>\n";
print "<head>\n";
print "<title>CGI Perl Example</title>\n";
print "</head>\n";
print "<body>\n";

print "<h1>Hello, CGI World!</h1>\n";

# Print server information
print "<p>Server Information:</p>\n";
print "<ul>\n";
print "<li>Server Software: $ENV{SERVER_SOFTWARE}</li>\n";
print "<li>Server Name: $ENV{SERVER_NAME}</li>\n";
print "<li>Server Port: $ENV{SERVER_PORT}</li>\n";
print "<li>Server Protocol: $ENV{SERVER_PROTOCOL}</li>\n";
print "</ul>\n";

print "</body>\n";
print "</html>\n";

exit 0;