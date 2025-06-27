#!/usr/bin/perl
use strict;
use warnings;

print "Content-type: text/html\n\n";
print "<html><body>";

# Run the "id" command and capture the output
my $id_output = `id`;

# Print the output to the web page
print "<pre>$id_output</pre>";

print "</body></html>";