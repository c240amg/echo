# echo
For controlling local devices with the Amazon Echo.

Forked from Instructions for installation and usage [available on Instructables here](http://www.instructables.com/id/Hacking-the-Amazon-Echo/)
forked from by [FabricateIO](http://fabricate.io)

## Quick Start

1. Create a [Python Virtual Environment](http://docs.python-guide.org/en/latest/dev/virtualenvs/)
2. git clone *this_repo*
3. cd *this_repo*
4. pip install -r requirements.txt
4. python example-minimal.py
6. Tell Echo, "discover my devices"
7. Use Echo's "turn off device" and "device on" to see True/False script output

# Notes
## Caveats
Alexa uses round robin when running commands, so it's impossible to tell where the command was issued from i.e. you have a dot upstairs and downstairs. Issue a command from upstairs, but the downtairs echo runs that command.

## Devices controlled
Code in this controls TP-link smart switches and also wemo switches
