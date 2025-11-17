#!/bin/bash
echo "Content-type: text/html"
echo ""
echo '<html>'
echo '<head>'
echo '<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">'
echo '<title>Command Output</title>'
echo '</head>'
echo '<body>'

# Run the "id" command and capture the output
id_output=$(id)

# Print the command output to the HTML page
echo "<pre>$id_output</pre>"

echo '</body>'
echo '</html>'
exit 0