import os
# def Rule(operation, source, dest, switch, protocol):
#     print("---------------------------------------------------------")
#     print("|"+operation +"|"+ source +"|" + dest +"|"+ switch+"|"+protocol)

class Rule:
    action = ""
    src = ""
    dest = ""
    switch = ""
    proto = ""
    def __init__(self,action1,src1,dest1,switch1,proto1):
        self.action = action1
        self.src = src1
        self.dest = dest1
        self.switch = switch1
        self.proto = proto1

fw = open('sample.sh', 'w')
fw.write('curl -X PUT http://localhost:8080/firewall/module/enable/0000000000000001\n')
fw.write('curl -X PUT http://localhost:8080/firewall/module/enable/0000000000000002\n')
#allow -s h1 -d h2 s2 -p icmp
#allow -s h2 -d h1 s1
#block -s h2 -d h1 s1 -p icmp
#block -s h1 -d h2 s2
#block -s h2 -d h1 s1 -p ipv6
start = "curl -X POST -d  "
ends1 = "http://localhost:8080/firewall/rules/0000000000000001"
ends2 = "http://localhost:8080/firewall/rules/0000000000000002"
h1 = "\"10.0.0.1/32\""
h2 = "\"10.0.0.2/32\""
switch = ""
s = ""
d = ""
list = []
#curl -X POST -d  '{"nw_src": "10.0.0.2/32", "nw_dst": "10.0.0.3/32", "nw_proto": "ICMP", "actions": "DENY", "priority": "10"}' http://localhost:8080/firewall/rules/0000000000000001
while True:
    print("\n>>>",end="")
    commandLine = input()
    if commandLine is "":
        continue
    if commandLine.startswith('allow'):
        var = commandLine
        b = [a_temp for a_temp in var.strip().split(' ')]
        #print(b)
        if b[1] != "-s" or b[3] != "-d":
            print("invalid")
        else:
            if b[2] == "h1":
                s = h1
                d = h2
            else:
                s = h2
                d = h1
            if b[5] == "s1":
                switch = ends1
            else:
                switch = ends2
            if len(b) == 6:
                final = start + '\'{"new_src": '+ s +', "nw_dst": '+d+'}\' '+ switch
                #print(final)
                r = Rule(b[0].upper(), s, d, b[5].upper(), "----")
                list.append(r)
                fw.write(final+'\n')
                print("RULE ADDED SUCCESSFULLY!!!")
            elif len(b) == 8:
                prot = b[7].upper()
                final = start + '\'{"new_src": ' + s + ', "nw_dst": ' + d +', "nw_proto": '+'\"'+prot+'\"' + '}\' ' + switch
                #print(final)
                r1 = Rule(b[0].upper(), s, d, b[5].upper(), prot)
                list.append(r1)
                fw.write(final+'\n')
                print("RULE ADDED SUCCESSFULLY!!!")
    if commandLine.startswith('block'):
        var = commandLine
        #print(var)
        b = [a_temp for a_temp in var.strip().split(' ')]
        #print(b)
        if b[1] != "-s" or b[3] != "-d":
            print("invalid")
        else:
            if b[2] == "h1":
                s = h1
                d = h2
            else:
                s = h2
                d = h1
            if b[5] == "s1":
                switch = ends1
            else:
                switch = ends2
            if len(b) == 6:
                final = start + '\'{"new_src": ' + s + ', "nw_dst": ' + d +', "actions": "DENY", "priority": "10"' +'}\' ' + switch
                #print(final)
                r2 = Rule(b[0].upper(), s, d, b[5].upper(),"----")
                list.append(r2)
                fw.write(final + '\n')
                print("RULE ADDED SUCCESSFULLY!!!")
            elif len(b) == 8:
                prot = b[7].upper()
                final = start + '\'{"new_src": ' + s + ', "nw_dst": ' + d + ', "nw_proto": ' + '\"' + prot + '\"' +', "actions": "DENY", "priority": "10"'+ '}\' ' + switch
                #print(final)
                r3 = Rule(b[0].upper(), s, d, b[5].upper(), prot)
                list.append(r3)
                fw.write(final + '\n')
                print("RULE ADDED SUCCESSFULLY!!!")
    if commandLine.startswith('table'):
        print("-------------------------------------------------------------")
        print("| Action |    Source    |   Destination   | Switch| Protocol|")
        print("-------------------------------------------------------------")
        for i in list:
            print("|  "+i.action+" | "+i.src+"| "+i.dest+"   |  "+i.switch+"   |  "+i.proto+"   | ")
            print("-------------------------------------------------------------")
    if commandLine.startswith('run'):
        fw.close()
        os.system("bash sample.sh")
    if commandLine.startswith('edit'):
        fw = open('sample.sh', 'w')
    if commandLine.startswith('help') or commandLine.startswith('?'):
        print("1. Allow (-s) src  (-d) dest  switch [protocol] :: adds firewall rule to \"Allow\" connection from src to dest for given protocol")
        print("2. Block (-s) src  (-d) dest  switch [protocol] :: adds firewall rule to \"Block\" connection from src to dest for given protocol")
        print("3. Run :: executes ACL rule on controller")
        print("4. Edit :: Allows user to edit firewall rules")
        print("5. Exit :: terminates the program")
    if commandLine.startswith('exit'):
        fw.close()
        #print(list)
        break
