#!/usr/bin/python

from zipfile import ZipFile
from io import BytesIO
from os import environ
import sys
import requests
import re

STEAM_CDN = environ.get("STEAM_CDN", "https://media.steampowered.com/client/")
CLIENT_MANIFEST = "steam_client_win32"
BINARY_BUNDLE = "bins_win32"
LINK_REGEX = re.compile(f'"{BINARY_BUNDLE}"\\s*{{\\s*"file"\\s+"([^"]*)"')
CLIENT_NAME = "steamclient.dll"

def fetch_latest_steamclient() -> bytes:
    manifest = requests.get(STEAM_CDN + CLIENT_MANIFEST).text
    bundle_name = LINK_REGEX.search(manifest).group(1)
    zipped_bundle = BytesIO(requests.get(STEAM_CDN + bundle_name).content)
    return ZipFile(zipped_bundle).read("steamclient.dll")

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else "steamclient.dll"
    with open(target, "wb") as f:
        f.write(fetch_latest_steamclient())