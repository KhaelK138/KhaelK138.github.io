#!/usr/bin/env python3
import os

print("Content-Type: text/plain\n")
print(os.popen("whoami").read())
