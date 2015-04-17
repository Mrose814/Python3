import sqlite3
import socket
import re
import shlex
import subprocess



#use Data::Dumper;
#use Net::DNS;
#use strict;

#use DBI;

def main():
    
    db = sqlite3.connect('auth.db')
    #my $dbh = DBI->connect("dbi:SQLite:dbname=auth.sqlite");

    cur = db.cursor()
    rows = cur.execute("SELECT ipnumber.ipnumber,username.username,attack.count FROM attack,ipnumber,username where attack.ip=ipnumber.id AND attack.username=username.id ORDER BY ipnumber.ipnumber")
    #my @rows = @{ $dbh->selectall_arrayref("SELECT ipnumber.ipnumber,username.username,attack.count FROM attack,ipnumber,username where attack.ip=ipnumber.id AND attack.username=username.id ORDER BY ipnumber.ipnumber") };


    #res = dns.resolver()
    #my $res = Net::DNS::Resolver->new;


    total = 0
    #my $total = 0;

    print("IP\t\t\tUsername\tCount")
    #print "IP\t\t\tUsername\tCount\n";

    print("==\t\t\t========\t=====")
    #print "==\t\t\t========\t=====\n";

    for row in rows:
    #foreach (@rows)

#        print("dumper")
        #   print  Dumper($_);
        ip = row[0]
        #   my $ip = @$_[0];
        username = row[1]
        #   my $username = @$_[1];
        count = row[2]
        #   my $count = @$_[2];
        additional_info = lookup(ip)
        #   my $additional_info = lookup($ip);


        print("{0:23s} {1:14s} {2:6d}".format(ip, username, count), "\t" "(",additional_info,")")


        total += count
        #   $total+=$count;

    print("\n")
    print("Total attacks = ", total)
    #print "Total attacks = $total\n";

    exit(0)
    #exit(0);


def lookup(ip):

    rem_host = ip
    retval = ''
    #    my $remote_host = ip;
    #    my $retval = "";
    
    ip_format = re.compile('(\d+)\.(\d+)\.(\d+)\.(\d+)')

    if (ip_format.match(rem_host)):
    #    if($remote_host =~ m/(\d+)\.(\d+)\.(\d+)\.(\d+)/)

        blocks = ip.split('.')
        rev_host = '.'.join(reversed(blocks))
        #	my $reverse_host = "$4.$3.$2.$1";
        
        arpa_query = 'dig +short ' + rev_host + 'in-addr.arpa PTR'
        #	my $rr;
        #	my $query = $res->query("${reverse_host}.in-addr.arpa",'PTR');

        arpa_proc = subprocess.Popen(shlex.split(arpa_query), stdout = subprocess.PIPE)
        

        if(arpa_query):
            retval += bytes.decode(arpa_proc.stdout.readline()).replace('"', '').rstrip()
            retval += ' '


    #	if(defined($query))
    #	{
    #	    foreach($query->answer)
    #	    {
    #		if($_->type eq 'PTR')
    #		{
    #		    print "  ... found DNS PTR record for $reverse_host: " . ($_->ptrdname) . "\n";
    #		    $retval = $_->ptrdname;
    #		}
    #	    }
    #	}
    #	




	# courtesy of CYMRU
        cymru_query = 'dig +short ' + rev_host + '.origin.asn.cymru.com TXT'
        #	$query = $res->query("${reverse_host}.origin.asn.cymru.com",'TXT');

        cymru_proc = subprocess.Popen(shlex.split(cymru_query), stdout = subprocess.PIPE)



        if(cymru_query):
            retval += bytes.decode(cymru_proc.stdout.readline()).replace('"', '').rstrip()
        

       # asn_query = 'dig +short ' + rev_host + '.origin.asn.cymru.com TXT'


#       splits = retval.split('|')
        regex = re.compile('(\d+)')
        asn = 'AS' + regex.search(retval).group(0)

        asn_query = 'dig +short ' + asn + '.asn.cymru.com TXT'

        asn_proc = subprocess.Popen(shlex.split(asn_query), stdout = subprocess.PIPE)


        if(asn_query):
            retval += bytes.decode(asn_proc.stdout.readline()).replace('"', '').rstrip()

    #	if(defined($query))
    #	{
    #	    foreach($query->answer)
    #	    {
    #		my $rr = $_;
    #		if($rr->type eq 'TXT')
    #		{
    #		    print "  ... found CYMRU TXT record for $reverse_host.origin.asn.cymru.com: " . ($rr->txtdata) . "\n";
    #		    $retval .= " " . $rr->txtdata;
    #		}
    #		
    #		# finally, try for an ASN description at asn.cymru.com
    #		my($asn,@rest) = split(/\|/,$rr->txtdata);
    #		$asn =~ s/ //g;
    #		my $query2 = $res->query("AS${asn}.asn.cymru.com",'TXT');
    #		if(defined($query2))
    #		{
    #		    foreach($query2->answer)
    #		    {
    #			my $rr = $_;
    #			if($rr->type eq 'TXT')
    #			{
    #			    print "  ... found CYMRU ASN description for asn AS$asn: " . ($rr->txtdata) . "\n";
    #			    $retval .= " " . $rr->txtdata;
    # 			}
    #		    }
    #		}
    #	    }
    #	}
    #   }




    return retval





main()