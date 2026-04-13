#!/usr/bin/env python

print("Content-type: text/html\n")

# Run the id command
import subprocess
result = subprocess.run(["id"], capture_output=True, text=True)

# Print the result to the web page
print("<html><body>")
print("<h2>Result of 'id' Command:</h2>")
print("<pre>{}</pre>".format(result.stdout))
print("</body></html>")