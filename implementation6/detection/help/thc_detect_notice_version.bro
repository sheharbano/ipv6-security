redef enum Notice::Type += {
		## THC IPv6 attack tool signature matched
		THCSignature,
		RoutingExtensionRType0,
		LinkLocalIP,
	};

event new_connection(c: connection)
	{
	local src = c$id$orig_h;
	local dst = c$id$resp_h;

	if ( (src in [fe80::]/10) || (dst in [fe80::]/10) )
		{
		NOTICE([$note=LinkLocalIP, $src=src,
				 $dst=dst,
				$msg="One of the connection ends is using an IPv6 link local address."
				]);
		}
	}

event ipv6_ext_headers(c: connection, p: pkt_hdr)
	{
	local idx=0;
	for ( idx in  p$ip6$exts )
		{
		if ( p$ip6$exts[idx]?$dstopts )
			{
			# Destination ignore option
			if ( p$ip6$exts[idx]$dstopts$options[0]$otype==31 )
				NOTICE([$note=THCSignature, $src=c$id$orig_h,
					 $dst=c$id$resp_h,
					$msg="Option type 31 in IPv6 destination extension header (THC IPv6 tool)"
					]);
				break;
			}
	
		if ( p$ip6$exts[idx]?$hopopts )
			{
			# Hop-by-hop ignore option
			if ( p$ip6$exts[idx]$hopopts$options[0]$otype==31 )
				NOTICE([$note=THCSignature, $src=c$id$orig_h,
					 $dst=c$id$resp_h,
					$msg="Option type 31 in IPv6 hop by hop extension header (THC IPv6 tool)"
					]);
				break;
			}

		if ( p$ip6$exts[idx]?$routing )
			{
			if ( p$ip6$exts[idx]$routing$rtype == 0 )
				{
				NOTICE([$note=RoutingExtensionRType0, $src=c$id$orig_h,
					 $dst=c$id$resp_h,
					$msg="RType=0 in IPv6 Routing Extension header"
					]);
				}
				
			}
		}
	}



