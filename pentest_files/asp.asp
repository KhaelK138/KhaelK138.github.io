<%@ Page Language="C#" %>
<!DOCTYPE html>

<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ASP.NET Whoami</title>
</head>
<body>
    <%
        // Execute the "whoami" command
        System.Diagnostics.Process process = new System.Diagnostics.Process();
        process.StartInfo.FileName = "whoami";
        process.StartInfo.UseShellExecute = false;
        process.StartInfo.RedirectStandardOutput = true;
        process.Start();

        // Read the output of the command
        string output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
    %>

    <pre><%= output %></pre>
</body>
</html>