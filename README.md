NAME
----

`bgpq3` - bgp filtering automation for Cisco and Juniper routers

SYNOPSIS
--------

```
	bgpq3 [-h host] [-S sources] [-EP] [-f asn | -G asn] [-346AbDdJjX] [-r len] [-R len] [-m max] [-W len] OBJECTS [...]
```

DESCRIPTION
-----------

The bgpq3 utility used to generate Cisco and Juniper prefix-lists,
extended access-lists, policy-statement terms and as-path lists based on
RADB data.

The options are as follows:

#### -3      

Assume that your device is asn32-capable.

#### -4 

Generate IPv4 prefix/access-lists (default).

#### -6      

Generate IPv6 prefix/access-lists (IPv4 by default).

#### -A      

Try to aggregate generated filters as much as possible (not all output formats
supported).

#### -b

Generate output in BIRD format (default: Cisco).

#### -d      

Enable some debugging output.

#### -D      

Use asdot notation for Cisco as-path access-lists.

#### -E      

Generate extended access-list (Cisco) or policy-statement term using
route-filters (Juniper).

#### -f `AS number`

Generate input as-path access-list for adjacent as `AS number`.

#### -G `number`

Generate output as-path access-list.

#### -h `host`

Host running IRRD database (default: `whois.radb.net`).

#### -J      

Generate config for Juniper (default: Cisco).

#### -j      

Generate output in JSON format (default: Cisco).

#### -m `length`

Maximum length of accepted prefixes (default: `32` for IPv4, `128` for IPv6).

#### -M `match`

Extra match conditions for Juniper route-filters. See the examples section.

#### -l `name`

`Name` of generated configuration stanza.

#### -P      

Generate prefix-list (default behaviour, flag added for backward compatibility
only).

#### -r `length`

Allow more-specific routes with masklen starting with specified length.

#### -R `length`

Allow more-specific routes up to specified masklen too.  (Please, note: objects
with prefix-length greater than specified length will be always allowed.)

#### -S `sources`

Use specified sources only (default: RADB,RIPE,APNIC).

#### -T      

Disable pipelining. (not recommended)

#### -W `length`

Generate as-path strings of a given length maximum (0 for infinity).

#### -X      

Generate config for Cisco IOS XR devices (plain IOS by default).

####  `OBJECTS`

`OBJECTS` means networks (in prefix format), autonomous systems, as-sets and
route-sets. If multiple objects are specified they will be merged.

EXAMPLES
--------

Generating named Juniper prefix-filter for `AS20597`:

     user@host:~>bgpq3 -Jl eltel AS20597
     policy-options {
     replace:
      prefix-list eltel {
         81.9.0.0/20;
         81.9.32.0/20;
         81.9.96.0/20;
         81.222.128.0/20;
         81.222.192.0/18;
         85.249.8.0/21;
         85.249.224.0/19;
         89.112.0.0/19;
         89.112.4.0/22;
         89.112.32.0/19;
         89.112.64.0/19;
         217.170.64.0/20;
         217.170.80.0/20;
      }
     }

For Cisco we can use aggregation (-A) flag to make this prefix-filter
more compact:

     user@host:~>bgpq3 -Al eltel AS20597
     no ip prefix-list eltel
     ip prefix-list eltel permit 81.9.0.0/20
     ip prefix-list eltel permit 81.9.32.0/20
     ip prefix-list eltel permit 81.9.96.0/20
     ip prefix-list eltel permit 81.222.128.0/20
     ip prefix-list eltel permit 81.222.192.0/18
     ip prefix-list eltel permit 85.249.8.0/21
     ip prefix-list eltel permit 85.249.224.0/19
     ip prefix-list eltel permit 89.112.0.0/18 ge 19 le 19
     ip prefix-list eltel permit 89.112.4.0/22
     ip prefix-list eltel permit 89.112.64.0/19
     ip prefix-list eltel permit 217.170.64.0/19 ge 20 le 20

and, as you see, prefixes `89.112.0.0/19` and `89.112.32.0/19` now aggregated 
into single entry 

	ip prefix-list eltel permit 89.112.0.0/18 ge 19 le 19.

Well, for Juniper we can generate even more interesting policy-statement,
using `-M <extra match conditions>`, `-r <len>`, `-R <len>` and hierarchical 
names:

     user@host:~>bgpq3 -AJEl eltel/specifics -r 29 -R 32 -M "community blackhole" AS20597
	policy-options {
	 policy-statement eltel {
	  term specifics {
	replace:
	   from {
	    community blackhole;
	    route-filter 81.9.0.0/20 prefix-length-range /29-/32;
	    route-filter 81.9.32.0/20 prefix-length-range /29-/32;
	    route-filter 81.9.96.0/20 prefix-length-range /29-/32;
	    route-filter 81.222.128.0/20 prefix-length-range /29-/32;
	    route-filter 81.222.192.0/18 prefix-length-range /29-/32;
	    route-filter 85.249.8.0/21 prefix-length-range /29-/32;
	    route-filter 85.249.224.0/19 prefix-length-range /29-/32;
	    route-filter 89.112.0.0/17 prefix-length-range /29-/32;
	    route-filter 217.170.64.0/19 prefix-length-range /29-/32;
	   }
	  }
	 }
	}


generated policy-option term now allows more-specific routes in range
/29 - /32 for eltel networks if they marked with community 'blackhole' 
(defined elsewhere in configuration).

Of course, `bgpq3` supports IPv6 (-6):

     user@host:~>bgpq3 -6l as-retn-6 AS-RETN6
     no ipv6 prefix-list as-retn-6
     ipv6 prefix-list as-retn-6 permit 2001:7fb:fe00::/48
     ipv6 prefix-list as-retn-6 permit 2001:7fb:fe01::/48
     [....]

and ASN32

     user@host:~>bgpq3 -J3f 112 AS-SPACENET
     policy-options {
     replace:
      as-path-group NN {
       as-path a0 "^112(112)*$";
       as-path a1 "^112(.)*(1898|5539|8495|8763|8878|12136|12931|15909)$";
       as-path a2 "^112(.)*(21358|23456|23600|24151|25152|31529|34127|34906)$";
       as-path a3 "^112(.)*(35052|41720|43628|44450|196611)$";
      }
     }

see `AS196611` in the end of the list ? That's `AS3.3` in 'asplain' notation.

If your router does not support ASN32 (yet) you should not use switch -3, 
and the result will be next:

     user@host:~>bgpq3 -f 112 AS-SPACENET
     no ip as-path access-list NN
     ip as-path access-list NN permit ^112( 112)*$
     ip as-path access-list NN permit ^112( [0-9]+)* (1898|5539|8495|8763)$
     ip as-path access-list NN permit ^112( [0-9]+)* (8878|12136|12931|15909)$
     ip as-path access-list NN permit ^112( [0-9]+)* (21358|23456|23600|24151)$
     ip as-path access-list NN permit ^112( [0-9]+)* (25152|31529|34127|34906)$
     ip as-path access-list NN permit ^112( [0-9]+)* (35052|41720|43628|44450)$

`AS196611` is no more in the list, however, `AS23456` (transition AS) would
have been added to list if it were not present.

DIAGNOSTICS
-----------

When everything is OK, `bgpq3` generates result to standard output and
exits with status == 0.  In case of errors they are printed to stderr and
program exits with non-zero status.

NOTES ON ULTRA-LARGE PREFIX-LISTS
---------------------------------

When using `bgpq3` to expand extra-large AS-SETs, `bgpq3` may stuck
due to lacking tcp buffer size. To avoid this, tune your OS. 
FreeBSD can be tuned in the following way:

    sysctl -w net.inet.tcp.sendbuf_max=16777216
    
Linux can be tuned in the following way:

    sysctl -w net.ipv4.tcp_window_scaling=1
    sysctl -w net.core.rmem_max=33554432
    sysctl -w net.core.wmem_max=33554432
    sysctl -w net.ipv4.tcp_rmem="4096 87380 33554432"
    sysctl -w net.ipv4.tcp_wmem="4096 65536 33554432"

Please note that generated prefix-lists may not fit your router's
limitations. For example, JunOS supports only 85,325 prefixes in 
each prefix-list [4](http://www.juniper.net/techpubs/en_US/junos11.4/topics/reference/configuration-statement/prefix-list-edit-policy-options.html). 


SEE ALSO
--------

1. [Routing Arbiter](http://www.radb.net/)
2. [draft-michaelson-4byte-as-representation-05.txt](http://www.ietf.org/internet-drafts/draft-michaelson-4byte-as-representation-05.txt)
     for information on 'asdot' and 'asplain' notations.
3. [Cisco documentation](http://www.cisco.com/en/US/prod/collateral/iosswrel/ps6537/ps6554/ps6599/data_sheet_C78-521821.html)
     for information on Cisco implementation of ASN32.
4. [JunOS prefix-lists limitation](http://www.juniper.net/techpubs/en_US/junos11.4/topics/reference/configuration-statement/prefix-list-edit-policy-options.html)

AUTHOR
------

Alexandre Snarskii [snar@snar.spb.ru](mailto:snar@snar.spb.ru)

Program Homepage
----------------

[http://snar.spb.ru/prog/bgpq3/](http://snar.spb.ru/prog/bgpq3/)

