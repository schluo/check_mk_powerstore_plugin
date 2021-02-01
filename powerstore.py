#!/usr/bin/env python3
# encoding: utf-8

__author__    = "Oliver Schlueter"
__copyright__ = "Copyright 2020, Dell Technologies"
__license__   = "GPL"
__version__   = "1.0.0"
__email__     = "oliver.schlueter@dell.com"
__status__    = "Production"

""""
############################################
#
#  DELL EMC PowerStore plugin for check_mk
#
############################################

#import modules"""
import argparse
import sys
import os
import re
import json
import requests
import urllib3
import csv
import collections
import datetime
import random

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

###########################################
#        VARIABLE
###########################################
DEBUG = False

module_arg = {
                'alerts': '--alerts',
                'stats': '--stats',
    }

###########################################
#    Methods
###########################################

def escape_ansi(line):
        ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]')
        return ansi_escape.sub('', str(line))

def get_argument():
    global hostaddress, user, password, module, arg_cmd, create_config, perfstats_type, consider_ack_alerts
    
    # appliance statitics are default
    perfstats_type = "appliance"
    
    try:
        # Setup argument parser
        parser = argparse.ArgumentParser()
        parser.add_argument('-H', '--hostname',
                            type=str,
                            help='hostname or IP address',
                            required=True)
        parser.add_argument('-u', '--username',
                            type=str,
                            help='username', dest='username',
                            required=True)
        parser.add_argument('-p', '--password',
                            type=str,
                            help='user password',
                            required=True)
        parser.add_argument('-m', '--module',
                            type=str,
                            choices=['alerts',
                                     'stats'],
                            help='Request statistics or alerts. Possible options are: alerts  | stats',
                            dest='module', required=True)
 #       parser.add_argument('-t', '--stats_type',
 #                           type=str,
 #                           choices=['appliance',
 #                                    'node',
 #                                    'volume',
 #                                    'cluster',
 #                                    'vm',
 #                                    'vg',
 #                                    'fe_fc_port',
 #                                    'fe_eth_port',
 #                                    'fe_eth_node',
 #                                    'fe_fc_node'],
 #                           help='Statistics metric type. Possible options are: appliance | node | volume | cluster | vm | vg | fe_fc_port | fe_eth_port | fe_eth_node | fe_fc_node',
 #                           dest='perfstats_type', required=False)
                            
        parser.add_argument('-c', '--config', action='store_true', help='build new metric config file',required=False, dest='create_config')
        parser.add_argument('-a', '--ack', action='store_true', help='consider also acknowledged alerts',required=False, dest='consider_ack_alerts')
        args = parser.parse_args()

    except KeyboardInterrupt:
        # handle keyboard interrupt #
        return 0

    hostaddress = args.hostname
    user = args.username
    password = args.password
    create_config = args.create_config
    consider_ack_alerts = args.consider_ack_alerts
    module = args.module.lower()
 #   if args.perfstats_type is not None:
 #       perfstats_type = args.perfstats_type
    arg_cmd = module_arg[module]


###########################################
#    CLASS
###########################################

class PowerStore():
    # This class permit to connect of the PowerStore's API

    def __init__(self):
        self.user = user
        self.password = password
        self.cmd = arg_cmd

    def send_request_stats(self):
        # send a request and get the result as dict
        global powerstore_stats
        global powerstore_token
                    
        try:
            # try to get token
            url = 'https://' + hostaddress + '/api/rest/cluster?select=name,state'            
            r = requests.get(url, verify=False, auth=(self.user, self.password))

            #if DEBUG:
            #    print(r, r.headers)
            
            # read access token from returned header
            powerstore_token = r.headers['DELL-EMC-TOKEN']
            
        except Exception as err:
            print(timestamp + ": Not able to get token: " + str(err))
            exit(1)        
        
        try:
            # try to get stats using token
            url = 'https://' + hostaddress + '/api/rest/metrics/generate'
            r = requests.post(url, verify=False, auth=(self.user, self.password), headers={"DELL-EMC-TOKEN":powerstore_token}, json={"entity": "performance_metrics_by_"+perfstats_type , "entity_id": "A1", "interval": "Five_Mins"})

            #if DEBUG:
            #    print(r, r.headers)
         
            # prepare return to analyse
            powerstore_stats = json.loads(r.content)
            
        except Exception as err:
            print(timestamp + ": Not able to get stats: " + str(err))
            exit(1)   
        

    def send_request_alerts(self):
        try:
            # send a request and get the result string list
            global powerstore_alerts
            
            url = 'https://' + hostaddress + '/api/rest/alert?select=name,severity,state,resource_name,generated_timestamp,is_acknowledged, events'
            r = requests.get(url, verify=False, auth=(self.user, self.password))
         
            #if DEBUG:
            #    print(r, r.headers) 
         
            # prepare return to analyse
            powerstore_alerts = json.loads(r.content)
            
        except Exception as err:
            print(timestamp + ": Not able to get health status: " + str(err))
            exit(1)

    def process_stats(self):
        self.send_request_stats()

        # initiate plugin output
        try:
            checkmk_output = "Perf Data successful loaded at " + timestamp +" | "
            check_mk_metric_conf = ""
            
            # just take last data set
            powerstore_last_stats = powerstore_stats[-1]
                      
            for perf_key, perf_value in powerstore_last_stats.items():
                
                # just process average and maximum values
                if "max" in perf_key or "avg" in perf_key:
                    
                    # transform to basic units
                    if "latency" in perf_key:
                        perf_value = perf_value / 1000000
                    if "utilization" in perf_key:
                        perf_value = perf_value * 100
                    
                    # generate metric name for plugin output
                    metric_full_name = perf_key.replace(' ','_')
                    
                    # generate metric description for metric config file
                    metric_description = perf_key.split("(")[0].replace("_"," ")
                    
                    # if command line option "-c" was set then create new metric config file
                    if create_config:
                        if "bandwidth" in perf_key: metric_unit = "bytes/s"
                        if "latency" in perf_key: metric_unit = "s"
                        if "iops" in perf_key: metric_unit = "1/s"
                        if "size" in perf_key: metric_unit = "bytes"
                        if "utilization" in perf_key: metric_unit = "%"
                    
                        # build diagram titles from metric keys
                        check_mk_metric_conf += 'metric_info["' + metric_full_name +'"] = { ' + "\n" + \
                            '    "title" : _("' + metric_description.title().replace("Io","IO").replace("Cpu","CPU") + '"),' + "\n" + \
                            '    "unit" : "' + metric_unit +'",' + "\n" + \
                            '    "color" : "' + self.random_color() + '",' + "\n" + \
                        '}' + "\n"
                        
                    checkmk_output += "'" + metric_full_name +"'=" + ("{:.4f}".format(perf_value)).rstrip('0').rstrip('.') + ";;;; "
            
            # print result to standard output
            print(checkmk_output)

            # if command line option "-c" was set
            if create_config:
                try:
                    fobj = open(metric_config_file,"w")
                    fobj.write(check_mk_metric_conf)
                    fobj.close()
                except Exception as err:
                    print(timestamp + ": Not able to write metric config file: " + str(err))
                    exit(1)

        except Exception as err:
            print(timestamp + ": Error while generating result output: " + str(err))
            exit(1)

        sys.exit(0)

    def analyse_alerts(self):

        self.send_request_alerts()
       
        if consider_ack_alerts:
            powerstore_alerts_Info =     [x for x in powerstore_alerts if (x['severity'] == 'Info'     and x['state'] == 'ACTIVE' )]
            powerstore_alerts_Minor =    [x for x in powerstore_alerts if (x['severity'] == 'Minor'    and x['state'] == 'ACTIVE' )]
            powerstore_alerts_Major =    [x for x in powerstore_alerts if (x['severity'] == 'Major'    and x['state'] == 'ACTIVE' )]
            powerstore_alerts_None =     [x for x in powerstore_alerts if (x['severity'] == 'None'     and x['state'] == 'ACTIVE' )]
            powerstore_alerts_Critical = [x for x in powerstore_alerts if (x['severity'] == 'Critical' and x['state'] == 'ACTIVE' )]
        else:
            powerstore_alerts_Info =     [x for x in powerstore_alerts if (x['severity'] == 'Info'     and x['state'] == 'ACTIVE' and x['is_acknowledged'] == 'true')]
            powerstore_alerts_Minor =    [x for x in powerstore_alerts if (x['severity'] == 'Minor'    and x['state'] == 'ACTIVE' and x['is_acknowledged'] == 'true')]
            powerstore_alerts_Major =    [x for x in powerstore_alerts if (x['severity'] == 'Major'    and x['state'] == 'ACTIVE' and x['is_acknowledged'] == 'true')]
            powerstore_alerts_None =     [x for x in powerstore_alerts if (x['severity'] == 'None'     and x['state'] == 'ACTIVE' and x['is_acknowledged'] == 'true')]
            powerstore_alerts_Critical = [x for x in powerstore_alerts if (x['severity'] == 'Critical' and x['state'] == 'ACTIVE' and x['is_acknowledged'] == 'true')]
        
        error_count = len(powerstore_alerts_Major) + len(powerstore_alerts_Critical)
        warning_count = len(powerstore_alerts_Minor)
        
        if DEBUG:
            print('Errors  : ', error_count)
            print('Warnings: ', warning_count)
            
        # descision for final return status
        if error_count > 0: 
            print(timestamp + " - Final status: Error")
        else:
            if warning_count > 0: 
                print(timestamp + " - Final status: Warning")
            else: 
                if error_count + warning_count  == 0: 
                    print(timestamp + " - Final status: Ok")
                
        if len(powerstore_alerts_Critical) > 0:
            print('=== Critical Errors ===')     
            for alert in powerstore_alerts_Critical:
                event=alert['events'][-1]
                if alert['resource_name'] != "":
                    print(alert['resource_name'] + ": " + event['description_l10n'])
                else:
                    print(event['description_l10n'])
          
        if len(powerstore_alerts_Major) > 0:
            print('=== Error ===')   
            for alert in powerstore_alerts_Major:
                event=alert['events'][-1]
                if alert['resource_name'] != "":
                    print(alert['resource_name'] + ": " + event['description_l10n'])
                else:
                    print(event['description_l10n'])
             
        if len(powerstore_alerts_Minor) > 0:
            print('=== Warnings ===')  
            for alert in powerstore_alerts_Minor:
                event=alert['events'][-1]
                if alert['resource_name'] != "":
                    print(alert['resource_name'] + ": " + event['description_l10n'])
                else:
                    print(event['description_l10n'])
                
        if error_count > 0: sys.exit(2)
        if warning_count > 0: sys.exit(1)
        if error_count + warning_count  == 0: sys.exit(0)

        sys.exit(3)

    # method to generate a random color in hex code
    def random_color(self):
        red = format(random.randrange(10, 254),'x');
        green = format(random.randrange(10, 254),'x');
        blue = format(random.randrange(10, 254),'x');
        return "#"+ red.zfill(2) + green.zfill(2) + blue.zfill(2)


def main(argv=None):
    # get and test arguments
    get_argument()

    # store timestamp
    global timestamp, metric_filter_file, metric_config_file
    timestamp = datetime.datetime.now().strftime("%d-%b-%Y (%H:%M:%S)")

    metric_config_file = os.path.dirname(__file__).replace("/lib/nagios/plugins", "/share/check_mk/web/plugins/metrics/powerstore_metric_" + hostaddress.replace(".","_")+ ".py")

    # display arguments if DEBUG enabled
    if DEBUG:
        print("hostname: "+hostaddress)
        print("user: "+user)
        print("password: "+password)
        print("module: "+module)
        print("stats_type:"+perfstats_type)
        print("args cmd: "+arg_cmd)
    else:
        sys.tracebacklimit = 0

    mypowerstore = PowerStore()

    # process stats
    if module == 'stats':
        mypowerstore.process_stats()

    # process health status
    else:
        mypowerstore.analyse_alerts()

if __name__ == '__main__':
    main()
    sys.exit(3)
