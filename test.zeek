global ips:table[addr] of set[string];

event http_header(c: connection, is_orig: bool, name: string, value: string)
{   
    local ip_src=c$http$id$orig_h;
    local u_agent=c$http$user_agent;
    if ( ip_src !in ips)
    {
        ips[ip_src]=[to_lower(u_agent)];
    }
    else
    {	
    	add ips[ip_src][to_lower(u_agent)];
    }       
}

event zeek_done()
{
    local i:addr;
    for ( i in ips)
        if (|ips[i]|>=3)
            print cat(i," is a proxy");
}
