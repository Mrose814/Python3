import sqlite3
import re
#from collection import 



def main():

    db = sqlite3.connect('auth.db')
    db.execute('PRAGMA foreign_keys=ON')
    cur = db.cursor()
    init_db(cur)
    
    expr1 = re.compile("^(\w\w\w)\s+(\d+)\s+(\d\d:\d\d:\d\d)")
    expr2 = re.compile("^(\w\w\w)\s+(\d+)\s+(\d\d:\d\d:\d\d)\s+\(none\)")
    expr3 = re.compile("^(\w\w\w)\s+(\d+)\s+(\d\d:\d\d:\d\d)\s+\(none\)\s+(\w+)")
    expr4 = re.compile("Failed password for (\w+) from (\d+.\d+.\d+.\d+)")

    services = dict()
    password_fail_ip = dict()
    password_fail_usrname = dict()
    
    count = 1
    with open('./auth.log') as log:
       for line in log:
            if(expr1.search(line)):
                if(expr2.search(line)):
                    if(expr3.search(line)):
                        key = expr3.search(line).group(4)
                        if(key not in services):
                            services.setdefault(key,1)
                            #print("new_Key : %s" % key)
                        else:
                            services[key] += 1
                            #print("Key : %s" % key)

                            if(key == "sshd"):
                                if(expr4.search(line)):
                                    match = expr4.search(line)
                                    ip_key = match.group(2)
                                    pass_key = match.group(1)

                                    if(ip_key not in password_fail_ip):
                                        password_fail_ip.setdefault(ip_key,[])
                                        password_fail_ip[ip_key].append(pass_key)
                                    else:
                                        password_fail_ip[ip_key].append(pass_key)

                                    add_ip(ip_key,cur)
                                    cur.execute("SELECT id FROM ipnumber WHERE ipnumber = ?", [ip_key]);
                                    ip_id = cur.fetchone()
                                    
                                    if(pass_key not in password_fail_usrname):
                                        password_fail_usrname.setdefault(pass_key,1)
                                    else:
                                        password_fail_usrname[pass_key] += 1
                                    #print(password_fail_usrname.items())

                                    cur.execute("INSERT INTO username (username) VALUES (?)", [pass_key])
                                    

                                    cur.execute("SELECT id FROM username WHERE username = ?", [pass_key]);
                                    usrname_id = cur.fetchone()
#                                    print("username ", pass_key," has username_id = ", usrname_id[0])

                                    cur.execute("SELECT id FROM attack WHERE ip = ? AND username = ?",(ip_id[0] ,usrname_id[0]));
                                    attack_id = cur.fetchone()


                                    if(attack_id):
                                        cur.execute("UPDATE attack SET count = count+1 WHERE ip = ? AND username = ?", (ip_id[0], usrname_id[0]))
                                    else:
                                        cur.execute("INSERT INTO attack (count,ip,username) VALUES (?,?,?)", (1, ip_id[0], usrname_id[0]))


                else:
                    print("Line %d has something other than '(none)'", count)


            else:
                print("no match")

            count += 1

    
    print ("Services found in auth\n")
    print ("======================\n")
    for K in services:
        print("\n", K, " : ", services[K])
    
                           
    db.commit()
    db.close()


def init_db(cur):
    crt_ip = 'CREATE TABLE ipnumber (id INTEGER PRIMARY KEY, ipnumber TEXT UNIQUE ON CONFLICT IGNORE)'
    crt_user = 'CREATE TABLE username (id INTEGER PRIMARY KEY, username TEXT UNIQUE ON CONFLICT IGNORE)'
    crt_attack = 'CREATE TABLE attack (id INTEGER PRIMARY KEY, count INTEGER, ip INTEGER, username INTEGER, FOREIGN KEY(ip) REFERENCES ipnumber(id), FOREIGN KEY(username) REFERENCES username(id))'
    cur.execute(crt_ip)
    cur.execute(crt_user)
    cur.execute(crt_attack)


def add_ip(val, cur):
    add = "INSERT INTO ipnumber (ipnumber) VALUES (?);"
    cur.execute(add,[val])
    
def add_att(val, cur):
    add = "INSERT INTO ipnumber (ipnumber) VALUES (?);"
    cur.execute(add,[val])

main()
