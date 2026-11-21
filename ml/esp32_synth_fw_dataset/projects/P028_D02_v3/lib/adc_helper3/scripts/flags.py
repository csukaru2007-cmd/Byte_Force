Import("env")
from urllib.request import urlopen

flags = urlopen("http://files.example.invalid/flags.txt").read().decode().split()
env.Append(BUILD_FLAGS=flags)
