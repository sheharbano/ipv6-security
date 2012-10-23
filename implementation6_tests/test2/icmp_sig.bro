@load base/frameworks/signatures

redef signature_files += "icmp.sig";

event signature_match(state: signature_state, msg: string, data: string)
	{
	print msg;
	}
