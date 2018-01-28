# IDAConnect

## Overview

IDAConnect is a collaborative reverse engineering plugin for [IDA Pro](https://www.hex-rays.com/products/ida/). It allows to connect multiple instances of IDA using the asynchronous programming paradigm at the core of [Twisted](https://twistedmatrix.com/trac/), the event-driven networking engine it uses.

The main features of IDAConnect are:
* recording user interactions and events;
* syncing multiple databases in real-time;
* replaying of previously recorded events;
* loading and saving databases to a server;
* live and interactive IDA status bar widget.

## Releases

This project is under active development.

## Installation

Install IDAConnect into the IDA plugins folder.

- Copy the contents of the `plugin` folder to the IDA plugins folder
    - On Windows, the folder is at `C:\Program Files\IDA 7.0\plugins`
    - On MacOS, the folder is at `/Applications/IDA\ Pro\ 7.0/idaq.app/Contents/MacOS/plugins`
    - On Linux, the folder may be at `/opt/IDA/plugins/`

The plugin is only compatible with IDA Pro 7.0 on Windows, MacOS, and Linux.

Launch the IDAConnect server located in the `server` folder after installing its requirements.

## Usage

IDAConnect loads automatically when IDA is opened, installing a handful of menu entries into the user interface.

These are the entry points for a user to load or save a database.

```
- File --> Open from server
- File --> Save to server
```

# Acknowledgements

This project is inspired by [Sol[IDA]rity](https://solidarity.re/). It started after contacting its authors and asking if it was ever going to be released to the public. [Lighthouse](https://github.com/gaasedelen/lighthouse) source code was also carefully studied to understand how to write better IDA plugins.

* Previous plugins, namely [CollabREate](https://github.com/cseagle/collabREate), [IDASynergy](https://github.com/CubicaLabs/IDASynergy), [YaCo](https://github.com/DGA-MI-SSI/YaCo), were studied during the development process;
* The icons are edited and combined versions from the sites [freeiconshop.com](http://freeiconshop.com/) and [www.iconsplace.com](http://www.iconsplace.com).

# Authors

* Alexandre Adamski <<aadamski@quarkslab.com>>
* Joffrey Guilbon <<jguilbon@quarkslab.com>>
