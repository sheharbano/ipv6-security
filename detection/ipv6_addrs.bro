module IPv6Addr;

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

	## Table for containing 'defined' option types for hop by hop and destination extension headers
	## as defined by IANA:
	## http://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xml#ipv6-parameters-2
	global iana_options: set[count] = { 0x00, 0x01, 0xc2, 0xc3, 0x04, 0x05, 0x26, 0x07, 0x08, 
						0xc9, 0x8A, 0x1e, 0x3e, 0x5e, 0x63, 0x7e, 0x8b, 0x8c, 
						0x9e, 0xbe, 0xde, 0xfe };

	## Event that can be handled to access the ipv6_addr
	## record as it is sent on to the logging framework.
	global log_ipv6_addr: event(rec: Info);

}

event bro_init()
	{
	Log::create_stream(IPv6Addr::LOG, [$columns=Info, $ev=log_ipv6_addr]);
	}

event new_connection(c: connection)
	{
	local src = c$id$orig_h;
	local dst = c$id$resp_h;
	local note = "";
	local msg = "";
	local do_log = F;	

	if ( (src in [2000::]/3) || (dst in [2000::]/3) )
		{
		if ( (src in [2001::]/16) || (dst in [2001::]/16) )
			{
			note = "GlobalUnicastAddress:Typical";
			# /32 subnets assigned to providers, they assign /48, /56, /64 to the customers.
			msg="Saw a typical global unicast IPv6 address (2001::/16).";
			do_log = T;
			}
		else if ( (src in [2001:db8::]/32) || (dst in [2001:db8::]/32) )
			{
			note = "GlobalUnicastAddress:ReservedDocumentation";
			msg="Saw global unicast IPv6 address which is reserved for use in documentation (2001:db8::/32).";
			do_log = T;
			}

		else if ( (src in [2001:678::]/29) || (dst in [2001:678::]/29) )
			{
			note = "GlobalUnicastAddress:PInTLDNameservers";
			msg="Saw global unicast IPv6 Provider Independent / anycasting TLD nameserver address (2001:678::/29).";
			do_log = T;
			}
		
		else if ( (src in [2002::]/16) || (dst in [2002::]/16) )
			{
			note = "GlobalUnicastAddress:6to4";
			msg="Saw global unicast IPv6 6to4 address (2002::/16).";
			do_log = T;
			}
		else
			{
			note = "GlobalUnicastAddress";
			msg="Saw global unicast IPv6 address (2000::/3).";
			do_log = T;
			}
		}
	else
		{
		if ( (src in [fe80::]/10) || (dst in [fe80::]/10) )
			{
			note = "LinkLocalIP";
			msg="Saw IPv6 link local address.";
			do_log = T;
			}
		else if ( (src in [::]/128) || (dst in [::]/128) )
			{
			note = "UnspecifiedAddress";
			msg="Saw IPv6 unspecified address (::/128).";
			do_log = T;
			}

		else if ( (src in [::1]/128) || (dst in [::1]/128) )
			{
			note = "LocalhostAddress";
			msg="Saw IPv6 localhost address (::1/128).";
			do_log = T;
			}
	
		else if ( (src in [fec0::]/10) || (dst in [fec0::]/10) )
			{
			note = "SiteLocalAddress";
			msg="Saw IPv6 deprecated site local address (fec0::/10).";
			do_log = T;
			}

		else if ( (src in [fc00::]/7) || (dst in [fc00::]/7) )
			{
			note = "UniqueLocalUnicastScopeAddress";
			msg="Saw IPv6 unique local unicast scope address (fc00::/7).";
			do_log = T;
			}

		else if ( (src in [fc00::]/7) || (dst in [fc00::]/7) )
			{
			note = "UniqueLocalUnicastScopeAddress";
			msg="Saw IPv6 unique local unicast scope address (fc00::/7).";
			do_log = T;
			}

		else if ( (src in [fc00::]/7) || (dst in [fc00::]/7) )
			{
			note = "UniqueLocalUnicastScopeAddress";
			msg="Saw IPv6 unique local unicast scope address (fc00::/7).";	
			do_log = T;
			}

		else if ( (src in [::]/96) || (dst in [::]/96) )
			{
			note = "IPv4CompatibleIPv6Address";
			msg="Saw deprecated IPv4 compatible IPv6 address (::/96).";
			do_log = T;
			}

		#else if ( (src in [::ffff:0:0]/96) || (dst in [::ffff:0:0]/96) )
		#	{
		#	note = "IPv4MappedIPv6Address";
		#	msg="Saw IPv4 mapped IPv6 address (::ffff:0:0/96).";
		#	}

		else if ( (src in [64:ff9b::]/96) || (dst in [64:ff9b::]/96) )
			{
			note = "GlobalUnicastAddress:IPv4asIPv6";
			msg="Saw global unicast IPv6 address representing an IPv4 address (64:ff9b::/96).";
			do_log = T;
			}

		else if ( (src in [3ffe::]/16) || (dst in [3ffe::]/16) )
			{
			note = "GlobalUnicastAddress:6Bone";
			msg="Saw global unicast IPv6 6Bone address which should not be seen (3ffe::/16).";
			do_log = T;
			}

		# Multicast addresses	
		else if ( (src in [ff00::]/8) || (dst in [ff00::]/8) )
			{
			# Determining if it's a global scope multicast
			local is_global_multicast = F;		
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
				do_log = T;
				}
			else
				{
				if ((src == [ff01::1]) || (dst == [ff01::1]))
					{
					note = "MulticastScopeAddress:AllNodesInterfaceLocal";
					msg="Saw IPv6 multicast scope address (ff01::1).";
					do_log = T;
					}
				else if ((src == [ff02::1]) || (dst == [ff02::1]))
					{
					note = "MulticastScopeAddress:AllNodesLinkLocal";
					msg="Saw IPv6 multicast scope address (ff01::1).";
					do_log = T;
					}

				else if ((src == [ff01::2]) || (dst == [ff01::2]))
					{
					note = "MulticastScopeAddress:AllRoutersInterfaceLocal";
					msg="Saw IPv6 multicast scope address (ff01::2).";
					do_log = T;
					}

				else if ((src == [ff02::2]) || (dst == [ff02::2]))
					{
					note = "MulticastScopeAddress:AllRoutersInterLinkLocal";
					msg="Saw IPv6 multicast scope address (ff02::2).";
					do_log = T;
					}
				else if ((src == [ff05::2]) || (dst == [ff05::2]))
					{
					note = "MulticastScopeAddress:AllRoutersSiteLocal";
					msg="Saw IPv6 multicast scope address (ff05::2).";
					do_log = T;
					}

				else if ((src == [ff05::1:3]) || (dst == [ff05::1:3]))
					{
					note = "MulticastScopeAddress:AllDHCPServersSiteLocal";
					msg="Saw IPv6 multicast scope address (ff05::1:3).";
					do_log = T;
					}

				else if ((src == [ff02::9]) || (dst == [ff02::9]))
					{
					note = "MulticastScopeAddress:AllRIPRoutersLinkLocal";
					msg="Saw IPv6 multicast scope address (ff02::9).";
					do_log = T;
					}

				else if ((src in [ff02::1:ff]/104) || (dst in [ff02::1:ff]/104))
					{
					note = "MulticastScopeAddress:SolicitedNode";
					msg="Saw IPv6 multicast scope address (ff02::1:ff]/104).";
					do_log = T;
					}

				else if ((src == [ff02::1:2]) || (dst == [ff02::1:2]))
					{
					note = "MulticastScopeAddress:AllDHCPRelayAgentsServersLinkLocal";
					msg="Saw IPv6 multicast scope address (ff02::1:2).";
					do_log = T;
					}

				else if ((src == [ff01::fb]) || (dst == [ff01::fb]))
					{
					note = "MulticastScopeAddress:DNSv6InterfaceLocal";
					msg="Saw IPv6 multicast scope address (ff01::fb).";
					do_log = T;
					}

				else if ((src == [ff02::fb]) || (dst == [ff02::fb]))
					{
					note = "MulticastScopeAddress:DNSv6LinkLocal";
					msg="Saw IPv6 multicast scope address (ff02::fb).";
					do_log = T;
					}

				else if ((src == [ff03::fb]) || (dst == [ff03::fb]))
					{
					note = "MulticastScopeAddress:DNSv6AdminLocal";
					msg="Saw IPv6 multicast scope address (ff03::fb).";
					do_log = T;
					}

				else if ((src == [ff05::fb]) || (dst == [ff05::fb]))
					{
					note = "MulticastScopeAddress:DNSv6SiteLocal";
					msg="Saw IPv6 multicast scope address (ff05::fb).";
					do_log = T;
					}
			
				else if ((src == [ff08::fb]) || (dst == [ff08::fb]))
					{
					note = "MulticastScopeAddress:DNSv6OrganizationalLocal";
					msg="Saw IPv6 multicast scope address (ff08::fb).";
					do_log = T;
					}

				else if ((src == [ff01::101]) || (dst == [ff01::101]))
					{
					note = "MulticastScopeAddress:NTPInterfaceLocal";
					msg="Saw IPv6 multicast scope address (ff01::101).";
					do_log = T;
					}
		
				else if ((src == [ff02::101]) || (dst == [ff02::101]))
					{
					note = "MulticastScopeAddress:NTPLinkLocal";
					msg="Saw IPv6 multicast scope address (ff02::101).";
					do_log = T;
					}

				else if ((src == [ff03::101]) || (dst == [ff03::101]))
					{
					note = "MulticastScopeAddress:NTPAdminLocal";
					msg="Saw IPv6 multicast scope address (ff03::101).";
					do_log = T;
					}

				else
					{
					note = "MulticastScopeAddress:NonGlobal";
					msg="Saw non-global IPv6 multicast scope address (ffX<any scope but e>::/8).";
					do_log = T;
					}
				}

			}

		else
			{
			note = "UnclassifiedAddress";
			msg="Saw IPv6 unclassified address.";
			do_log = T;
			}	
		}

	if ( do_log )
		{
		local ipv6_addr_info: IPv6Addr::Info;

		ipv6_addr_info$ts = network_time();
		ipv6_addr_info$src_ip = src;
		ipv6_addr_info$src_port = c$id$orig_p;
		ipv6_addr_info$dst_ip = dst;
		ipv6_addr_info$dst_port = c$id$resp_p;
		ipv6_addr_info$note = note;
		ipv6_addr_info$msg = msg;

		Log::write(IPv6Addr::LOG,ipv6_addr_info);
		}	
	}


