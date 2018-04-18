# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
import os
import shutil
import sys
import urllib2
import zipfile

import ida_diskio
import ida_loader

# Allow the user to override the download URL
if 'URL' not in locals():
    URL = 'https://github.com/IDArlingTeam/IDArling/archive/master.zip'

print('[*] Installing IDArling...')
if os.name == 'nt':
    # Install into the user directory on Windows
    userDir = ida_diskio.get_user_idadir()
    if not os.path.exists(userDir):
        os.makedirs(userDir, 0755)
    destDir = os.path.join(userDir, 'idarling')
    if not os.path.exists(destDir):
        os.makedirs(destDir, 0755)
else:
    # Install into the plugins directory on Linux
    destDir = os.path.join(ida_diskio.idadir(None), 'plugins')

print('[*] Downloading master.zip archive...')
archivePath = os.path.join(destDir, 'master.zip')
if os.path.exists(archivePath):
    os.remove(archivePath)
with open(archivePath, 'wb') as f:
    f.write(urllib2.urlopen(URL).read())

print('[*] Unzipping master.zip archive...')
archiveDir = os.path.join(destDir, 'IDArling-master')
if os.path.exists(archiveDir):
    shutil.rmtree(archiveDir)
with zipfile.ZipFile(archivePath, 'r') as zip:
    for zipfile in zip.namelist():
        if zipfile.startswith(os.path.basename(archiveDir)):
            zip.extract(zipfile, destDir)

print('[*] Moving the IDArling files...')
srcPath = os.path.join(archiveDir, 'idarling_plugin.py')
dstPath = os.path.join(destDir, os.path.basename(srcPath))
if os.path.exists(dstPath):
    os.remove(dstPath)
shutil.move(srcPath, dstPath)
srcDir = os.path.join(archiveDir, 'idarling')
dstDir = os.path.join(destDir, os.path.basename(srcDir))
if os.path.exists(dstDir):
    shutil.rmtree(dstDir)
shutil.move(srcDir, dstDir)

print('[*] Removing master.zip archive...')
if os.path.exists(archivePath):
    os.remove(archivePath)
if os.path.exists(archiveDir):
    shutil.rmtree(archiveDir)

print('[*] Loading IDArling into IDA Pro...')
if os.name == 'nt':
    content = '''
#-----BEGIN IDARLING-----
import os
import ida_diskio
import ida_kernwin
import ida_loader

def load():
    userDir = ida_diskio.get_user_idadir()
    pluginDir = os.path.join(userDir, 'idarling')
    pluginPath = os.path.join(pluginDir, 'idarling_plugin.py')
    ida_loader.load_plugin(pluginPath)
ida_kernwin.register_timer(0, load)
#-----END IDARLING-----
    '''
    sys.path.append(destDir)
    exec(content)

    print('[*] Editing idapythonrc.py file...')
    userDir = ida_diskio.get_user_idadir()
    idapyrcPath = os.path.join(userDir, 'idapythonrc.py')
    idapyrcContent = ''
    if os.path.exists(idapyrcPath):
        with open(idapyrcPath, 'r') as f:
            idapyrcContent = f.read()

    if content.split('\n')[1] not in idapyrcContent:
        with open(idapyrcPath, 'a') as f:
            f.write(content)
else:
    pluginPath = os.path.join(destDir, 'idarling_plugin.py')
    ida_loader.load_plugin(pluginPath)

print('[*] IDArling installed successfully!')
