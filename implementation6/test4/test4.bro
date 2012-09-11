## Generated for every IPv6 packet that contains extension headers.
## This is potentially an expensive event to handle if analysing IPv6 traffic
## that happens to utilize extension headers frequently.
##
## c: The connection the packet is part of.
##
## p: Information from the header of the packet that triggered the event.
##
## .. bro:see:: new_packet tcp_packet packet_contents esp_packet
event ipv6_ext_headers(c: connection, p: pkt_hdr)
	{
	#print |p$ip6$exts|;
	#for (idx in p$ip6$exts)
	#	print p$ip6$exts[idx]$hopopts;
	#print p$ip6$exts[0]$dstopts;
	#print p$ip6$exts[0]$routing;
	#print p$ip6$exts[0]$fragment;
	#print p$ip6$exts[0]$ah;
	#print p$ip6$exts[0]$esp;
	#print p$ip6$exts[0]$mobility;

	local test4 = T;
	if ( |p$ip6$exts| == 128 )
		{
		for ( idx in p$ip6$exts  )
			{
			if ( !p$ip6$exts[idx]?$hopopts )
				{
				 test4 = F;
				 break;
				}
			}
		if ( test4 )
			print "THC test 4";
		}

	}
