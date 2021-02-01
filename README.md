Plugin to integrate Dell EMC PowerStore Systems into Check_MK

Although the plugin is designed to be used in Check_MK it is implemented as a NAGIOS plugin with Check_MK specific extentions. Thereofore it should be also possible to used it in NAGIOS.

Installation

Copy the plugin to /opt/omd/sites/<site name>/local/lib/nagios/plugins folder.

CLI Syntax:

usage: powerstore.py [-h] -H HOSTNAME -u USERNAME -p PASSWORD -m
                     {alerts,stats} [-c] [-a]

optional arguments:
  -h, --help            show this help message and exit
  -H HOSTNAME, --hostname HOSTNAME
                        hostname or IP address
  -u USERNAME, --username USERNAME
                        username
  -p PASSWORD, --password PASSWORD
                        user password
  -m {alerts,stats}, --module {alerts,stats}
                        Request statistics or alerts. Possible options are:
                        alerts | stats
  -c, --config          build new metric config file
  -a, --ack             consider also acknowledged alerts

The plugin can be used to get performance values as well as health status.
To get performance values use the "-m stats" option. 
To get health status information use the "-m alerts" option.
To initially create the metric config file use the -c option (directly from the CLI not from Check_MK/nagio)
Use the -a option to see also alertes that are active but already acknowledged by the Powerstore UI user.

Usage of the plugin within CheckMK
Define a check within Check_MK under "Classical active and passive Monitoring checks". 
