# zombie-pharmer

Open either Shodan search results, a specified IP range, a
single IP, or domain and perform an [ipidseq probing using nmap](https://nmap.org/nsedoc/scripts/ipidseq.html).

Shamefully inspired from [device-pharmer](https://github.com/DanMcInerney/device-pharmer) by Dan McInerney. The code is simple and meant to be auditable. The parallelism is achieved using nmap's one.

Logs all hosts which sport incremental ip ids using either the Shodan search term or the target IPs/domain + _results.txt.
Note that for a successful probing, the command must be ran as root.

One should note that Shodan only allows the first page of results (100 hosts) if you are using their free API key. If you have their professional API key you can specify the number of search result pages to test with the -n NUMBER_OF_PAGES argument. By default it will only check page 1.

Requirements:
-----
Python 2.7
* [libnmap](https://github.com/savon-noir/python-libnmap)
* shodan (if giving the -s option)

Modern unices
* Tested on Kali 1.0.9a
* Tested on MacOS

Shodan API Key (only if you are giving the -s SEARCHTERM argument)
* Give the script the -a YOUR_API_KEY argument OR
* Edit line 62 to do it permanently. Don't have an API key? Get one free easily [from shodan](http://www.shodanhq.com/account/register)... alternatively, explore your [Google dorking skills](http://danmcinerney.org/how-to-exploit-home-routers-for-anonymity/) before downloading some Shodan ones .


Usage
-----

``` shell
sudo python zombie-pharmer.py -s "printer" -a Wutc4c3T78gRIKeuLZesI8Mx2ddOiP4
```
Search Shodan for "printer" using the specified API key and probe each result host for being a suitable zombie

### All options:

-a APIKEY: use this API key when searching Shodan (only necessary in conjunction with -s)

-c CONCURRENT: maps to nmap option --min-hostgroup; default=1000

--ipfile IPTEXTFILE: test each IP in a list of newline-separated IPs from the specified text file

-n NUMPAGES: go through specified amount of Shodan search result pages collecting IPs; 100 results per page

-s SEARCHTERMS: search Shodan for term(s)

-t IPADDRESS/DOMAIN/IPRANGE: try hitting this domain, IP, or IP range instead of using Shodan to populate the targets list and return response information
