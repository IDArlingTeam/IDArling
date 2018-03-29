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
import zipfile
import urllib2

import idaapi

MASTER_LOCATION = 'https://github.com/IDAConnect/IDAConnect/archive/master.zip'
FILES_TO_MOVE = ['idaconnect_plugin.py', 'idaconnect/']

print('[*] Installing IDAConnect...')
pluginsDir = os.path.join(idaapi.idadir(None), 'plugins')
archivePath = os.path.join(pluginsDir, 'master.zip')
masterDir = os.path.join(pluginsDir, 'IDAConnect-master')

print('[*] Downloading master.zip archive...')
if os.path.exists(archivePath):
    os.remove(archivePath)
with open(archivePath, 'wb') as f:
    f.write(urllib2.urlopen(MASTER_LOCATION).read())

print('[*] Unzipping master.zip archive...')
if os.path.exists(masterDir):
    shutil.rmtree(masterDir)
with zipfile.ZipFile(archivePath, 'r') as z:
    for zf in z.namelist():
        if zf.startswith('IDAConnect-master/'):
            z.extract(zf, pluginsDir)

print('[*] Moving the IDAConnect files...')
for filename in FILES_TO_MOVE:
    masterPath = os.path.join(masterDir, filename)
    pluginPath = os.path.join(pluginsDir, filename)
    if os.path.exists(pluginPath):
        if os.path.isdir(pluginPath):
            shutil.rmtree(pluginPath)
        if os.path.isfile(pluginPath):
            os.remove(pluginPath)
    shutil.move(masterPath, pluginPath)

print('[*] Removing master.zip archive...')
if os.path.exists(archivePath):
    os.remove(archivePath)
if os.path.exists(masterDir):
    shutil.rmtree(masterDir)

print('[*] Loading IDAConnect into IDA Pro...')
pluginPath = os.path.join(pluginsDir, 'idaconnect_plugin.py')
idaapi.load_plugin(pluginPath)

print('[*] IDAConnect installed successfully!')
