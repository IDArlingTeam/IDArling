# IDAConnect

## Overview

IDAConnect is a collaborative reverse engineering plugin for [IDA Pro](https://www.hex-rays.com/products/ida/) and [Hex-Rays](https://www.hex-rays.com/products/decompiler/index.shtml). It allows to connect multiple instances of IDA using the asynchronous programming paradigm at the core of [Twisted](https://twistedmatrix.com/trac/), the event-driven networking engine.

The main features of IDAConnect are:
* recording user interactions and events;
* syncing multiple databases in real-time;
* replaying of previously recorded events;
* loading and saving databases to a server;
* live and interactive IDA status bar widget;
* and even more...

## Releases

This project is under active development. Feel free to send a PR if you would like to help! :-)

**It is not really usable in its current state, please stayed tuned for a first release of the project!**

## Installation

Install the IDAConnect client into the IDA plugins folder.

- Copy the contents of the `plugin` folder to the IDA plugins folder.
    - On Windows, the folder is at `C:\Program Files\IDA 7.0\plugins`
    - On MacOS, the folder is at `/Applications/IDA\ Pro\ 7.0/idaq.app/Contents/MacOS/plugins`
    - On Linux, the folder may be at `/opt/IDA/plugins/`
- Install the requirements using `pip` and the `requirements.txt` file.

*Warning:* The plugin is only compatible with IDA Pro 7.0 on Windows, MacOS, and Linux.

Launch the IDAConnect server located in the `server` folder after installing its requirements.

## Usage

IDAConnect loads automatically when IDA is opened, installing a handful of menu entries into the user interface.

First use the widget in the status bar to connect to the server. Then you will be able to access the following menus:

```
- File --> Open from server
- File --> Save to server
```

# Acknowledgements

This project is inspired by [Sol[IDA]rity](https://solidarity.re/). It started after contacting its authors and asking if it was ever going to be released to the public. [Lighthouse](https://github.com/gaasedelen/lighthouse) source code was also carefully studied to understand how to write better IDA plugins.

* Previous plugins, namely [CollabREate](https://github.com/cseagle/collabREate), [IDASynergy](https://github.com/CubicaLabs/IDASynergy), [YaCo](https://github.com/DGA-MI-SSI/YaCo), were studied during the development process;
* The icons are edited and combined versions from the sites [freeiconshop.com](http://freeiconshop.com/) and [www.iconsplace.com](http://www.iconsplace.com).

Thanks to Quarkslab for allowing this release.

# Authors

* Alexandre Adamski <<aadamski@quarkslab.com>>
* Joffrey Guilbon <<jguilbon@quarkslab.com>>
