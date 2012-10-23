
## Check complete list of assigned/known options types for hop by hop and destination headers at
## (http://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xml#ipv6-parameters-2)

event ipv6_ext_headers(c: connection, p: pkt_hdr)
	{
	for ( idx in  p$ip6$exts[0]$hopopts$options )
		{
		if ( p$ip6$exts[0]$hopopts$options[idx]$otype == 31 )
			print "test case 1";
		}
	}
