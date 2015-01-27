#!/usr/bin/env python2
# -*- coding: utf-8 -*-

'''
Concurrently open either Shodan search results, a specified IP range, a
single IP, or domain and perform an ipidseq probing using nmap. Note that
for a successful probing, the command must be ran as root.

Shamefully inspired from device-pharmer.py by Dan McInerney
(please see https://github.com/DanMcInerney/device-pharmer )

requires:   linux / mac
            Python 2.7
                libnmap
                shodan


__author__ = mrmacete
             protonmail: mrmacete
'''

import argparse

import re
from sys import exit

from libnmap.process import NmapProcess
from libnmap.parser import NmapParser

import os

#############################################################################
# argument parsing, shodan search and input checking
# Taken from device-pharmer.py by Dan McInerney with minor modification
#############################################################################

def parse_args():
   """Create the arguments"""
   parser = argparse.ArgumentParser(
   formatter_class=argparse.RawDescriptionHelpFormatter,
   epilog='-----------------------------------------------------------------------------------\n'
          'Examples:\n\n'
          '  -Search Shodan for "printer" using the specified API key and probe each\n'
          '   result host for being a suitable zombie:\n\n'
          '      sudo python zombie-pharmer.py -s "printer" -a Wutc4c3T78gRIKeuLZesI8Mx2ddOiP4\n\n')

   parser.add_argument("-a", "--apikey", help="Your api key")
   parser.add_argument("-c", "--concurrent", default='1000', help="Enter number of concurrent requests to make; default = 1000")
   parser.add_argument("-n", "--numpages", default='1', help="Number of pages deep to go in Shodan results with 100 results per page; default is 1")
   parser.add_argument("-s", "--shodansearch", help="Your search terms")
   parser.add_argument("-t", "--targets", help="Enter an IP, a domain, or a range of IPs to fetch (e.g. 192.168.0-5.1-254 will"
                       "fetch 192.168.0.1 to 192.168.5.254; if using a domain include the subdomain if it exists: sub.domain.com or domain.com)")
   parser.add_argument("--ipfile", help="Test IPs from a text file (IPs should be separated by newlines)")
   return parser.parse_args()

def shodan_search(search, apikey, pages, ipfile):
    import shodan

    if apikey:
        API_KEY = apikey
    else:
        API_KEY = 'ENTER YOUR API KEY HERE AND KEEP THE QUOTES'

    api = shodan.Shodan(API_KEY)

    ips_found = []

    # Get IPs from Shodan search results
    try:
        results = api.search(search, page=1)
        total_results = results['total']
        print '[+] Results: %d' % total_results
        print '[*] Page 1...'
        pages = max_pages(pages, total_results)
        for r in results['matches']:
            ips_found.append('%s:%s' % (r['ip_str'], r['port']))

        if pages > 1:
            i = 2
            while i <= pages:
                results = api.search(search, page=i)
                print '[*] Page %d...' % i
                for r in results['matches']:
                    ips_found.append('%s:%s' % (r['ip_str'], r['port']))
                i += 1

        return ips_found

    except Exception as e:
        print '[!] Shodan search error:', e

def get_ips_from_file(ipfile):
    ''' Read IPs from a file '''
    ips_found = []
    try:
        with open(ipfile) as ips:
            for line in ips:
                ip = line.strip()
                ips_found.append(ip)
    except IOError:
        exit('[!] Are you sure the file %s exists in this directory?' % ipfile)

    return ips_found

def input_check(args):
    ''' Check for multi inputs, or lack of target inputs '''
    if not args.targets and not args.shodansearch and not args.ipfile:
        exit('[!] No targets found. Use the -s option to specify a search term for Shodan, the -t option to specify an IP, IP range, or domain, or use the --ipfile option to read from a list of IPs in a text file')

    inputs = 0
    if args.targets:
        inputs += 1
    if args.shodansearch:
        inputs += 1
    if args.ipfile:
        inputs += 1
    if inputs > 1:
        exit('[!] Multiple target inputs specified, choose just one target input option: -t (IP, IP range, or domain), -s (Shodan search results), or --ipfile (IPs from a text file)')


def max_pages(pages, total_results):
    ''' Measures the max # of pages in Shodan results. Alternative to this
    would be to measure len(results['matches']) and stop when that is zero,
    but that would mean 1 extra api lookup which would add some pointless
    seconds to the search '''

    total_pages = (total_results+100)/100
    if pages > total_pages:
        pages = total_pages
        return pages
    else:
        return pages
#############################################################################

def split_target(target):
    hp = target.split(':')

    port = '80'
    host = hp[0]

    if len(hp) == 2:
        port = hp[1]

    return (str(host), str(port))

class Nmapper():
    def __init__(self, args):
        self.search = args.shodansearch

        self.nmap_options_fmt = self.build_nmap_options_fmt(args.concurrent)


    def _whereis(self, program):
        ''' this is ripped from libnmap code '''
        
        for path in os.environ.get('PATH', '').split(':'):
            if (os.path.exists(os.path.join(path, program)) and not
               os.path.isdir(os.path.join(path, program))):
                return os.path.join(path, program)
        return None

    def run(self, port, hosts):

        print "[*] Probing %d hosts on port %s" % (len(hosts), port)        

        opts = self.build_nmap_options(port)

        print "nmap {0}".format(opts)

        nm = NmapProcess(hosts, options=opts, fqp=self._whereis("nmap") )
        rc = nm.run()

        if nm.rc == 0:
            nmap_report = NmapParser.parse(nm.stdout)

            for scanned_host in nmap_report.hosts:
                if self.is_ipidseq_incremental( scanned_host ):
                    for open_port in scanned_host.get_open_ports():
                        self.final_print(scanned_host.ipv4, open_port[0], 'FOUND')


    def build_nmap_options(self, port):

        # scan always the given port and 80 for compatibility

        scanports = [ port ]

        if port != '80':
            scanports.append('80')
        
        return self.nmap_options_fmt.format(port) + ' -p ' + (','.join(scanports))

    def build_nmap_options_fmt(self, concurrent):
        opts = [    
        '-n',   # do not use DNS
        '-Pn',  # do not use ping
        '--script ipidseq --script-args probeport={0}', # ipidseq string on given port
        '--min-hostgroup {0}'.format(concurrent) # set minimum host group to given concurrency
        ]
            
        return ' '.join(opts)


    def is_ipidseq_incremental(self, host):
        return len([s for s in host.scripts_results if s['id'] == 'ipidseq' and s['output'] == 'Incremental!']) > 0

    def final_print(self, host, port, label):
        if self.search:
            name = self.search
        elif self.targets:
            name = self.targets
        elif self.ipfile:
            name = self.ipfile

        name = name.replace('/', '')

        results = '[*] %s:%s | %s' % (host, port, label)
        with open('%s_results.txt' % name, 'a+') as f:
            f.write('[*] %s:%s | %s\n' % (host, port, label))
        print results


#############################################################################
# IP range target handlers
# Taken from against.py by pigtails23 with minor modification
#############################################################################
def get_targets_from_args(targets):
    target_type = check_targets(targets)
    if target_type:
        if target_type == 'domain' or target_type == 'ip':
            return ['%s' % targets]
        elif target_type == 'ip range':
            return ip_range(targets)

def check_targets(targets):
    ''' This could use improvement but works fine would be
    nice to get a good regex just for finding IP ranges '''
    if re.match('^[A-Za-z]', targets): # starts with a letter
        return 'domain'
    elif targets.count('.') == 3 and '-' in targets:
        return 'ip range'
    #if re.match('(?=.*-)', targets):
    #    return 'ip range'
    elif re.match(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$", targets):
        return 'ip'
    else:
        return None

def handle_ip_range(iprange):
    parted = tuple(part for part in iprange.split('.'))
    rsa = range(4)
    rsb = range(4)
    for i in range(4):
        hyphen = parted[i].find('-')
        if hyphen != -1:
            rsa[i] = int(parted[i][:hyphen])
            rsb[i] = int(parted[i][1+hyphen:]) + 1
        else:
            rsa[i] = int(parted[i])
            rsb[i] = int(parted[i]) + 1
    return rsa, rsb

def ip_range(iprange):
    rsa, rsb = handle_ip_range(iprange)
    ips = []
    counter = 0
    for i in range(rsa[0], rsb[0]):
        for j in range(rsa[1], rsb[1]):
            for k in range(rsa[2], rsb[2]):
                for l in range(rsa[3], rsb[3]):
                    ip = '%d.%d.%d.%d' % (i, j, k, l)
                    ips.append(ip)
    return ips
#############################################################################


def group_by_port(targets):
    group = {}

    for target in targets:
        host, port = split_target(target)

        if port in group:
            group[port].append(host)
        else:
            group[port] = [ host ]

    return group


def main(args):

    S = Nmapper(args)

    input_check(args)

    if args.targets:
        targets = get_targets_from_args(args.targets)
    elif args.shodansearch:
        targets = shodan_search(args.shodansearch, args.apikey, int(args.numpages), args.ipfile)
    elif args.ipfile:
        targets = get_ips_from_file(args.ipfile)

    if targets == [] or targets == None:
        exit('[!] No valid targets')

    group = group_by_port(targets)

    for port in group:
        S.run(port, group[port])


if __name__ == "__main__":
    main(parse_args())
