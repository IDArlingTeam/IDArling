<p align="center">
    <img src="https://i.imgur.com/9Vxm0Fn.png" />
</p>

## Overview

IDArling is a collaborative reverse engineering plugin for [IDA Pro](https://www.hex-rays.com/products/ida/)
and [Hex-Rays](https://www.hex-rays.com/products/decompiler/index.shtml). It
allows to synchronize in real-time the changes made to a database by multiple
users, by connecting together different instances of IDA Pro.

The main features of IDArling are:
* live recording and replaying of all user interactions;
* loading and saving of IDA databases to a central server;
* interactive IDA status bar widget and custom dialogs;
* Python plugin and server with no extra dependencies;
* and even more to come...

If you have any questions not worthy of a bug report, feel free to ping us at
[#idarling on freenode](https://kiwiirc.com/client/irc.freenode.net/idarling)
and ask away.

## Releases

This project is under active development. Feel free to send a PR if you would
like to help! :-)

**It is not really stable in its current state, please stayed tuned for a first
release of the project!**

## Installation

Install the IDArling client into the IDA plugins folder.

- Copy `idarling_plugin.py` and the `idarling` folder to the IDA plugins folder.
    - On Windows, the folder is at `C:\Program Files\IDA 7.0\plugins`
    - On macOS, the folder is at `/Applications/IDA\ Pro\ 7.0/idaq.app/Contents/MacOS/plugins`
    - On Linux, the folder may be at `/opt/IDA/plugins/`
- Alternatively, you can use the "easy install" method by copying the following
line into the console:
```
import urllib2; exec(urllib2.urlopen('https://raw.githubusercontent.com/IDArlingTeam/IDArling/master/easy_install.py')).read()
```

**Warning:** The plugin is only compatible with IDA Pro 7.0 on Windows, macOS,
and Linux.

The dedicated server requires PyQt5, which is integrated into IDA. If you're
using an external Python installation, we recommand using Python 3, which offers
a pre-built package that can be installed with a simple `pip install PyQt5`.

## Usage

IDArling loads automatically when IDA is opened, installing new elements into
the user interface.

First use the widget in the status bar to add the server of your choice in the
*Network Settings*. Then connect to the server using the widget again. Finally,
you should be able to access the following menus:

```
- File --> Open from server
- File --> Save to server
```

## FAQ

* Where is my old servers?

In commit `08eca13d4ecd51cd518cb54546f971e3b43edf04`, the config file name was
changed from `state.json` to `config.json` to enhance the config file storage.
Thus, your old servers won't be displayed in your server list. But don't worry,
you can still find them in your previous config file. The path of your config
file depends your platform. For example, under Linux, the path should be
`$HOME/.idapro/idarling/files/state.json`.

# Thanks

This project is inspired by [Sol[IDA]rity](https://solidarity.re/). It started
after contacting its authors and asking if it was ever going to be released to
the public. [Lighthouse](https://github.com/gaasedelen/lighthouse) source code
was also carefully studied to understand how to write better IDA plugins.

* Previous plugins, namely [CollabREate](https://github.com/cseagle/collabREate),
[IDASynergy](https://github.com/CubicaLabs/IDASynergy),
[YaCo](https://github.com/DGA-MI-SSI/YaCo), were studied during the development
process;
* The icons are edited and combined versions from the sites [freeiconshop.com](http://freeiconshop.com/)
and [www.iconsplace.com](http://www.iconsplace.com).

Thanks to Quarkslab for allowing this release.

# Authors

* Alexandre Adamski <<neat@idarling.re>>
* Joffrey Guilbon <<patate@idarling.re>>
