#!/bin/bash
cd $(dirname $0)
prefix_list='google sahchoo5theevaa8peel'
tld_list='com net org pro info biz tel name travel aero mobi xxx me tv bz cc ag hn lc mn sc vc ru com.ru net.ru org.ru pp.ru spb.ru msk.ru su co.uk xn--p1ai'
for tld in $tld_list; do
    for prefix in $prefix_list; do
        domain="$prefix.$tld"
        echo $domain
        whois_options="-H"
        if [[ $tld = *ru ]]; then whois_options="-H -h whois.nic.ru" ; fi
        test -f $domain || {
            whois $whois_options $domain > $domain
            sleep 1
        }
    done
done
