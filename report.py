import sqlite3
import socket
import re
import shlex
import subprocess




def main():
    
    db = sqlite3.connect('auth.db')

    cur = db.cursor()
    rows = cur.execute("SELECT ipnumber.ipnumber,username.username,attack.count FROM attack,ipnumber,username where attack.ip=ipnumber.id AND attack.username=username.id ORDER BY ipnumber.ipnumber")


   


    total = 0
    

    print("IP\t\t\tUsername\tCount")

    print("==\t\t\t========\t=====")

    for row in rows:

        ip = row[0]
        username = row[1]
        count = row[2]
        additional_info = lookup(ip)


        print("{0:23s} {1:14s} {2:6d}".format(ip, username, count), "\t" "(",additional_info,")")


        total += count

    print("\n")
    print("Total attacks = ", total)

    exit(0)


def lookup(ip):

    rem_host = ip
    retval = ''
    
    
    ip_format = re.compile('(\d+)\.(\d+)\.(\d+)\.(\d+)')

    if (ip_format.match(rem_host)):

        blocks = ip.split('.')
        rev_host = '.'.join(reversed(blocks))

        arpa_query = 'dig +short ' + rev_host + 'in-addr.arpa PTR'

        arpa_proc = subprocess.Popen(shlex.split(arpa_query), stdout = subprocess.PIPE)
        

        if(arpa_query):
            retval += bytes.decode(arpa_proc.stdout.readline()).replace('"', '').rstrip()
            retval += ' '


   
        cymru_query = 'dig +short ' + rev_host + '.origin.asn.cymru.com TXT'
       
        cymru_proc = subprocess.Popen(shlex.split(cymru_query), stdout = subprocess.PIPE)



        if(cymru_query):
            retval += bytes.decode(cymru_proc.stdout.readline()).replace('"', '').rstrip()
        



        regex = re.compile('(\d+)')
        asn = 'AS' + regex.search(retval).group(0)

        asn_query = 'dig +short ' + asn + '.asn.cymru.com TXT'

        asn_proc = subprocess.Popen(shlex.split(asn_query), stdout = subprocess.PIPE)


        if(asn_query):
            retval += bytes.decode(asn_proc.stdout.readline()).replace('"', '').rstrip()

   



    return retval





main()
