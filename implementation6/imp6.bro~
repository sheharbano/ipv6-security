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
	local idx = 0;
	# Test case 17: source-routing (rtype = 0)
	for ( idx in p$ip6$exts )
		{
		if ( p$ip6$exts[idx]?$routing )
			{
			if ( p$ip6$exts[idx]$routing$rtype == 0 )
				print "Test case 17: source-routing (rtype = 0)";
			}
		}


	if ( |p$ip6$exts| == 1 )
		{
		if ( p$ip6$exts[0]?$dstopts )
			{
			# Test case 5: destination ignore option
			for ( idx in p$ip6$exts[0]$dstopts$options )
				{
				if ( p$ip6$exts[0]$dstopts$options[idx]$otype == 31 )
					{
					# test 5 for option 1 $ otype == 31, but since it is specific to THC, so i am checking all indices
					print "THC test case 5: destination ignore option";
					break;
					}
				}
			# Test case 6: destination ignore option 2kb size
			if ( p$ip6$exts[0]$dstopts$len == 255 )
				print "THC test case 6: destination ignore option 2kb size";
			}
		

	
		}

	else if ( |p$ip6$exts| == 2 )
		{
		# Test case 3: 2 hop by hop options
		if ( p$ip6$exts[0]?$hopopts && p$ip6$exts[1]?$hopopts )
			print "THC test case 3:  2 hop by hop options";

		# Test case 7: 2 destination headers
		else if ( p$ip6$exts[0]?$dstopts && p$ip6$exts[1]?$dstopts )
			print "THC test case 7:  2 destination options";
		}

	
	else if ( |p$ip6$exts| == 128 )
		{
		# Test case 4: 128 hop by hop options
		# Test case 8: 128 destination headers
		local test4 = T;
		local test8 = T;
		for ( idx in p$ip6$exts  )
			{
			if ( !p$ip6$exts[idx]?$hopopts )
				{
				 test4 = F;
				 break;
				}

			if ( !p$ip6$exts[idx]?$dstopts )
				{
				 test8 = F;
				 break;
				}
			}
		if ( test4 )
			print "THC test case 4: 128 hop by hop options";
		if ( test8 )
			print "THC test case 8: 128 destination headers";

		
		}

	else if ( |p$ip6$exts| == 2000 )
		{
		# Test case 9: 2000 destination headers
		local test9 = T;
		for ( idx in p$ip6$exts  )
			{
			if ( !p$ip6$exts[idx]?$dstopts )
				{
				 test9 = F;
				 break;
				}
			}

		if ( test9 )
			print "THC test case 9: 2000 destination headers";

		
		}

	}
