module IPv6Weird;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:                time             &log;
		src_ip:            addr             &log;
		src_port:	   port		    &log;
		dst_ip:	   	   addr		    &log;
		dst_port:	   port		    &log; 
		note:		   string           &log;
		msg:		   string           &log;
	};
	
	redef record connection += {
	conn: Info &optional;};

	## Threshold for maximum number of extension headers per packet 
	const th_ext_headers = 5 &redef;

	## Table for containing 'defined' option types for hop by hop and destination extension headers
	## as defined by IANA:
	## http://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xml#ipv6-parameters-2
	global iana_options: set[count] = { 0x00, 0x01, 0xc2, 0xc3, 0x04, 0x05, 0x26, 0x07, 0x08, 
						0xc9, 0x8A, 0x1e, 0x3e, 0x5e, 0x63, 0x7e, 0x8b, 0x8c, 
						0x9e, 0xbe, 0xde, 0xfe };

	## Event that can be handled to access the ipv6_weird
	## record as it is sent on to the logging framework.
	global log_ipv6_weird: event(rec: Info);

}

event bro_init()
	{
	Log::create_stream(IPv6Weird::LOG, [$columns=Info, $ev=log_ipv6_weird]);
	}

event new_connection(c: connection)
	{
	local src = c$id$orig_h;
	local dst = c$id$resp_h;
	local note = "";
	local msg = "";	
	local is_weird = F;

	
	if ( (src in [fe80::]/10) || (dst in [fe80::]/10) )
		{
		note = "LinkLocalIP";
		msg="Saw IPv6 link local address.";
		is_weird = T;
		}

	else if ( (src in [::]/128) || (dst in [::]/128) )
		{
		note = "UnspecifiedAddress";
		msg="Saw IPv6 unspecified address (::/128).";
		is_weird = T;
		}

	else if ( (src in [::1]/128) || (dst in [::1]/128) )
		{
		note = "LocalhostAddress";
		msg="Saw IPv6 localhost address (::1/128).";
		is_weird = T;
		}

	else if ( (src in [fec0::]/10) || (dst in [fec0::]/10) )
		{
		note = "SiteLocalAddress";
		msg="Saw IPv6 deprecated site local address (fec0::/10).";
		is_weird = T;
		}

	else if ( (src in [fc00::]/7) || (dst in [fc00::]/7) )
		{
		note = "UniqueLocalUnicastScopeAddress";
		msg="Saw IPv6 unique local unicast scope address (fc00::/7).";
		is_weird = T;
		}

	else if ( (src in [::]/96) || (dst in [::]/96) )
		{
		note = "IPv4CompatibleIPv6Address";
		msg="Saw deprecated IPv4 compatible IPv6 address (::/96).";
		is_weird = T;
		}

	else if ( (src in [3ffe::]/16) || (dst in [3ffe::]/16) )
		{
		note = "GlobalUnicastAddress:6Bone";
		msg="Saw global unicast IPv6 6Bone address which should not be seen (3ffe::/16).";
		is_weird = T;
		}

	# Multicast addresses	
	else if ( (src in [ff00::]/8) || (dst in [ff00::]/8) )
		{
		# Determining if it's a global scope multicast
		local is_global_multicast = F;	
		is_weird = T;	
		local str_src = "";
		local str_dst = "";
		local idx = 0;
	
		if ( src in [ff00::]/8 )
			{
			str_src = fmt("%s",src);
			idx = strstr( str_src, "e");
			if ( idx == 4 )
				is_global_multicast = T;
			}
		else
			{
			str_dst = fmt("%s",dst);
			# Nibble 4 in ff00::/8 indicates scope. 'e' is for global scope
			idx = strstr( str_dst, "e");
			if ( idx == 4 )
				is_global_multicast = T;
			}

			
		if ( is_global_multicast )
			{
			note = "MulticastScopeAddress:Global";
			msg="Saw IPv6 multicast scope address (ffXe::/8 global scope).";
			}
		else
			{
			note = "MulticastScopeAddress:NonGlobal";
			msg="Saw non-global IPv6 multicast scope address (ff00::/8).";
			}
	
		}
	if ( is_weird )
		{
		local ipv6_weird_info: IPv6Weird::Info;

		ipv6_weird_info$ts = network_time();
		ipv6_weird_info$src_ip = src;
		ipv6_weird_info$src_port = c$id$orig_p;
		ipv6_weird_info$dst_ip = dst;
		ipv6_weird_info$dst_port = c$id$resp_p;
		ipv6_weird_info$note = note;
		ipv6_weird_info$msg = msg;

		Log::write(IPv6Weird::LOG,ipv6_weird_info);
		}		
	}



event ipv6_ext_headers(c: connection, p: pkt_hdr)
	{
	local ipv6_weird_info: IPv6Weird::Info;
	local src = c$id$orig_h;
	local dst = c$id$resp_h;

	# Check if number of extensions exceeds threshold
	if ( |p$ip6$exts| > th_ext_headers )
		{
		ipv6_weird_info$ts = network_time();
		ipv6_weird_info$src_ip = src;
		ipv6_weird_info$src_port = c$id$orig_p;
		ipv6_weird_info$dst_ip = dst;
		ipv6_weird_info$dst_port = c$id$resp_p;
		ipv6_weird_info$note = "TooManyExtensionHeaders";
		ipv6_weird_info$msg = fmt("Number of extensions:%d", |p$ip6$exts|);

		Log::write(IPv6Weird::LOG,ipv6_weird_info);		
		}

	local idx=0;
	local opt_idx=0;
	local msg = "";
	local note = "";

	for ( idx in p$ip6$exts )
		{
		if ( p$ip6$exts[idx]?$dstopts )
			{
			if( p$ip6$exts[idx]$dstopts?$options )
				{
				for ( opt_idx in  p$ip6$exts[idx]$dstopts$options ) 
					{
					if ( p$ip6$exts[idx]$dstopts$options[idx]?$otype )
						{ 
						if ( p$ip6$exts[idx]$dstopts$options[idx]$otype !in iana_options )
							{
							# Destination ignore option
							if ( p$ip6$exts[idx]$dstopts$options[idx]$otype==31 )
								{	
								msg = "Option type 31 in IPv6 destination extension header (THC IPv6 tool)";
								note = "Dest:OptionType:THC";
								}
							else
								{
								msg = "Undefined option type in IPv6 destination extension header";
								note = "Dest:OptionType:Undefined";
								}

							ipv6_weird_info$ts = network_time();
							ipv6_weird_info$src_ip = src;
							ipv6_weird_info$src_port = c$id$orig_p;
							ipv6_weird_info$dst_ip = dst;
							ipv6_weird_info$dst_port = c$id$resp_p;
							ipv6_weird_info$note = note;
							ipv6_weird_info$msg = msg;

							Log::write(IPv6Weird::LOG,ipv6_weird_info);
							break;		
							}
						}
					}
				}
			}
	
		if ( p$ip6$exts[idx]?$hopopts )
			{
			if ( p$ip6$exts[idx]$hopopts?$options )
				{	
				for ( opt_idx in p$ip6$exts[idx]$hopopts$options ) 
					{
					if ( p$ip6$exts[idx]$hopopts$options[idx]?$otype )
						{
						if ( p$ip6$exts[idx]$hopopts$options[idx]$otype !in iana_options )
							{
							# Destination ignore option
							if ( p$ip6$exts[idx]$hopopts$options[idx]$otype==31 )
								{	
								msg = "Option type 31 in IPv6 hop by hop extension header (THC IPv6 tool)";
								note = "HopByHop:OptionType:THC";
								}
							else
								{
								msg = "Undefined option type in IPv6 hop by hop extension header";
								note = "HopByHop:OptionType:Undefined";
								}

							ipv6_weird_info$ts = network_time();
							ipv6_weird_info$src_ip = src;
							ipv6_weird_info$src_port = c$id$orig_p;
							ipv6_weird_info$dst_ip = dst;
							ipv6_weird_info$dst_port = c$id$resp_p;
							ipv6_weird_info$note = note;
							ipv6_weird_info$msg = msg;

							Log::write(IPv6Weird::LOG,ipv6_weird_info);
							break;		
							}
						}
					}
				}
			}

		if ( p$ip6$exts[idx]?$routing )
			{
			if ( p$ip6$exts[idx]$routing?$rtype )
				{
				if ( p$ip6$exts[idx]$routing$rtype == 0 )
					{
					ipv6_weird_info$ts = network_time();
					ipv6_weird_info$src_ip = src;
					ipv6_weird_info$src_port = c$id$orig_p;
					ipv6_weird_info$dst_ip = dst;
					ipv6_weird_info$dst_port = c$id$resp_p;
					ipv6_weird_info$note = "Routing:RType0";
					ipv6_weird_info$msg = "RType=0 in IPv6 Routing Extension header (THC IPv6 tool)";

					Log::write(IPv6Weird::LOG,ipv6_weird_info);
					break;		
					}
				}
			}

		}
	}




