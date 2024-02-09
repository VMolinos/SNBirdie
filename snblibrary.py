# SNBirdie_Library


# AUXILIARY LIBRARIES
#------------------------------------------------------------------------------------
import sys
import types
import psutil
import random
import subprocess
import scapy.all as scapy
#pip install python-nmap
"""
import nmap
aux = nmap.PortScanner()
cap = aux.scan('192.168.74.131',arguments='-sT --reason')
ports = cap['scan']['192.168.74.131']['tcp'].keys()
ports = list(ports)
for port in ports:
    state = cap['scan']['192.168.74.131']['tcp'][ports[0]]['state']
    print("Port: {} --> state: {}".format(port,state))
"""


# KILL_CHILDREN  
#------------------------------------------------------------------------------------
def kill_sons(proc_pid):
    """kill_children METHOD:
    
        * Operation: kill any child processes process with <proc_pid> pid. 
        * Method used by the following methods: -
        * Use the following methods: -
        * Libraries needed: psutil.
        
        * Input arguments:
            -proc_pid: process PID. <Int type>.
        
        * Output arguments: -
    """
    
    process = psutil.Process(proc_pid)
    for proc in process.children(recursive=True):
        proc.kill()

    

# MESSAGE_SETTINGS
#------------------------------------------------------------------------------------
class message_settings:
    """message_settings CLASS:
        * Operation: set common message parameters.
        * Class used by the following functions: message_configurator.
        * Use the following methods: -.
        * Libraries needed: -.
    """
    
    def __init__(self):
        self.title = ''
        self.mode_flag = ''
        self.inconclusive = False
        self.filt = ''
        self.data = ''
        self.ports = []
        
    def set_title(self,title):
        self.title = title
        
    def set_mode_flag(self,mode_flag):
        self.mode_flag = mode_flag
        
    def set_inconclusive(self,inconclusive):
        self.inconclusive = inconclusive
    
    def set_filt(self,filt):
        self.filt = filt
        
    def set_data(self,data):
        self.data = data
        
    def set_ports(self,ports):
        for port in ports:
            self.ports.append(port)
        
  

# MESSAGE_CONFIGURATOR
#------------------------------------------------------------------------------------  
def message_configurator(tst_messages,pt_messages,single,all_titles,sending_out_iface,sending_out_ip4,sending_out_ip6,listening_in_ip4,listening_in_ip6,
                         broadcastip,multicastip4,multicastip6,localip4,localip6,loopbackip4,loopbackip6,flood,verbose):
    """message_configurator METHOD:
    
        * Operation: generate a list of message objects with all settings.
        * Method used by the following methods: -.
        * Use the following methods: -.
        * Use the following clases: message_settings.
        * Libraries needed: scapy,types,subprocess.
        
        * Input arguments:
            -tst_messages: indicates that only tst messages should be sent. <Bool type>.            ##Attention!## -> (If -tst_messages is True and 
            -pt_messages: indicates that only pt messages should be sent. <Bool type>.              -pt_messages is True, all messages will be sent)
            -single: indicates the set of messages that should be sent. <List type>
            -all_titles: causes the method returns the tst_titles and pt_titles lists. <Bool type>. 
            -sending_out_iface: sending interface in OUT_BOUND machine. <String type>. 
            -sending_out_ip4: IPv4 address for sending messages on the OUT_BOUND machine. <String type>.
            -sending_out_ip6: IPv6 address for sending messages on the OUT_BOUND machine. <String type>.
            -listening_in_ip4: IPv4 address to listen for traffic on the IN_BOUND machine. <String type>.
            -listening_in_ip6: IPv6 address to listen for traffic on the IN_BOUND machine. <String type>.
            -broadcastip: broadcast IP4. <String type>.
            -multicastip4: multicast IP4. <String type>.
            -multicastip6: multicast IP6. <String type>.
            -loopbackip4: loopbackIP IP4. <String type>.
            -loopbackip6: loopbackIP IP6. <String type>.
            -localip4: local IP4. <String type>.
            -localip6: local IP4. <String type>.
            -flood: number of messages for flooding. <Int type>
            -verbose: indicates if the verbose mode was selected. <Bool type>.
        
        * Output arguments (all_titles==True): 
            -tst_titles: all tst titles. <List type>
            -pt_titles: all pt titles. <List type>
        *Output arguments (all_titles==False):
            -messages: a list of message objects with all configuratinos.
    """
    
    tst_titles = ["IPv4_fragment_overlap","IPv6_fragment_overlap","TCP_Same_dst_and_src_IPv4","TCP_Same_dst_and_src_IPv6","ICMPv4_Ping_of_death","ICMPv6_Ping_of_death",
            "TCP_NULL_IPv4","TCP_SYN_FIN_IPv4","TCP_FIN_IPv4","TCP_SYN_RST_IPv4","TCP_NULL_IPv6","TCP_SYN_FIN_IPv6","TCP_FIN_IPv6","TCP_SYN_RST_IPv6","UDP_Bomb_IPv4",
            "UDP_DoS_Chargen_IPv4","UDP_Bomb_IPv6","UDP_DoS_Chargen_IPv6","ICMPv4_flood","ICMPv6_flood","TCP_flood_IPv4","TCP_flood_IPv6","IPv4_protocol_scanning",
            "IPv6_protocol_scanning","TCP_port_scanning_IPv4","TCP_port_scanning_IPv6","UDP_port_scanning_IPv4","UDP_port_scanning_IPv6","ICMPv4_host_discovery",
            "ICMPv6_host_discovery","LFI_attack"]
                
    pt_titles = ["TCP_Broadcast","TCP_Universal_Broadcast","TCP_Multicast_IPv4","TCP_Multicast_IPv6","TCP_Loopback_IPv4","TCP_Loopback_IPv6","TCP_Unspecified_IPv4",
                "TCP_Unspecified_IPv6","TCP_Source_Routing","TCP_Strict_Source_Routing","TCP_Record_Route","TCP_Timestamp","TCP_Security","TCP_Malformed","TCP_Incomplete_1",
                "TCP_Incomplete_2","TCP_Extended_Security","TCP_Commercial_Security","TCP_Link_Local_source_IPv4","TCP_Link_Local_source_IPv6","TCP_Link_Local_destination_IPv4",
                "TCP_Link_Local_destination_IPv6","TCP_port_scanning_with_CONNECT"]
    
    
    if all_titles:
        return tst_titles,pt_titles
    
    else:
        
        purple = '\033[1;35m'
        reset_color = '\033[1;0m'
        
        messages = [] # List of configured messages
    
        if tst_messages and pt_messages and not(single):
            titles = tst_titles + pt_titles
        elif tst_messages and not(single):
            titles = tst_titles
        elif pt_messages and not(single):
            titles = pt_titles
        elif single:
            aux_titles = tst_titles + pt_titles
            indexes = [x-1 for x in single]
            titles = [aux_titles[i] for i in indexes]
    
    
    
        for title in titles:
            message = message_settings()
            
            ## TST Messages   
            if title == "IPv4_fragment_overlap": # IPv4 fragment overlap
                message.set_title(title)
                message.set_mode_flag('TST')
                message.set_inconclusive (False)
                message.set_filt("less 70 and tcp and src host " + sending_out_ip4 + " and dst host " + listening_in_ip4 + " and src port 80 and dst port 80")
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                        frags = scapy.fragment(scapy.IP(dst=listening_in_ip4)/scapy.TCP(sport=9999, dport=9999)/('FAKE'*(1464//4)))
                        frags[1][scapy.Raw].load=scapy.struct.pack("!HH", 80, 80)
                        frags[1][scapy.IP].frag = 0
                        command = []
                        for _ in range(5):
                            command.append(frags[0])
                            command.append(frags[1])
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
        
                    target.sender = types.MethodType(sender,target)
                sender_patch(message)
                    
                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]):
                            checks.append(True)
                        
                        return checks   
                            
                    target.check = types.MethodType(check,target)
                check_patch(message)
                
                messages.append(message)
                        
            elif title == "IPv6_fragment_overlap": # IPv6 fragment overlap
                message.set_title(title)
                message.set_mode_flag('TST')
                message.set_inconclusive (False)
                message.set_data(title + "AAAAAAAAAA" + "&" + title + "BBBBBBBBBB")
                message.set_filt("ip6 and ip6 src host " + sending_out_ip6 + " and ip6 dst host " + listening_in_ip6)
                
                def sender_patch(target):
                    def sender(target,title,ports,data):                      
                        payload1 = title + 'A'*1272
                        payload2 = title + 'B'*1280
                        

                        ipv6_1 = scapy.IPv6(src=sending_out_ip6, dst=listening_in_ip6, plen=1288)
                        icmpv6 = scapy.ICMPv6EchoRequest(cksum=0x36dd, data=payload1)

                        frag1 = scapy.IPv6ExtHdrFragment(offset=0, m=1, id=511, nh=58)
                        frag2 = scapy.IPv6ExtHdrFragment(offset=1, m=0, id=511, nh=58)

                        packet1 = ipv6_1/frag1/icmpv6
                        packet2 = ipv6_1/frag2/payload2
                        
                        command = []
                        for _ in range(5):
                            command.append(packet1)
                            command.append(packet2)
                            
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                            
                    target.sender = types.MethodType(sender,target)
                sender_patch(message)
                
                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        data = data.split("&")
                        
                        for packet in capture: 
                            if packet.haslayer("Raw") and (data[1] in packet["Raw"].fields["load"].decode()): # If there are Raw layer in packet and contains the key message ("BBBBBB") in data.
                                checks.append(True)   
                            
                        return checks
                            
                    target.check = types.MethodType(check,target)
                check_patch(message)
                
                messages.append(message)
                
            elif title == "TCP_Same_dst_and_src_IPv4": # TCP Same dst and src IPv4
                message.set_title(title)
                message.set_mode_flag('TST')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_ports(['8001','8002','8003','8004','8005']) 
                message.set_filt("less 100 and tcp and src host " + listening_in_ip4 + " and dst host " + listening_in_ip4 
                                    + " and (port " + message.ports[0] + " or port " + message.ports[1] + " or port " + message.ports[2] 
                                    + " or port " + message.ports[3] + " or port " + message.ports[4] + ")")
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                        ports = [int(x) for x in ports]
                        command = scapy.IP(src=listening_in_ip4,dst=listening_in_ip4)/scapy.TCP(sport=ports)/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                            
                    target.sender = types.MethodType(sender,target)
                sender_patch(message)
                
                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]): # If there are TCP packets in pcap.
                            for packet in capture: 
                                if packet.haslayer("Raw") and (data in packet["Raw"].fields["load"].decode()): # If there are Raw layer in packet and contains the key message in data.
                                    checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)
                
                messages.append(message)
                
            elif title == "TCP_Same_dst_and_src_IPv6": # TCP Same dst and src IPv6
                message.set_title(title)
                message.set_mode_flag('TST')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_ports(['8001','8002','8003','8004','8005']) 
                message.set_filt("less 100 and tcp and ip6 src host " + listening_in_ip6 + " and ip6 dst host " + listening_in_ip6 
                                    + " and (port " + message.ports[0] + " or port " + message.ports[1] + " or port " + message.ports[2] 
                                    + " or port " + message.ports[3] + " or port " + message.ports[4] + ")")
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                        ports = [int(x) for x in ports]
                
                        command = scapy.IPv6(src=listening_in_ip6,dst=listening_in_ip6)/scapy.TCP(sport=ports)/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                            
                    target.sender = types.MethodType(sender,target)
                sender_patch(message)
                
                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]): # If there are TCP packets in pcap.
                            for packet in capture: 
                                if packet.haslayer("Raw") and (data in packet["Raw"].fields["load"].decode()): # If there are Raw layer in packet and contains the key message in data.
                                    checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)
                
                messages.append(message)
                
            elif title == "ICMPv4_Ping_of_death": # ICMPv4 Ping of death
                message.set_title(title)
                message.set_mode_flag('TST')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_filt("icmp and icmp[4]==0xff and icmp[5]==0xff and dst host " + listening_in_ip4)
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                
                        payload = data + " " + ("A"*6000)
                    
                        command = scapy.IP(dst=listening_in_ip4)/scapy.ICMP(id=65535,seq=65535)/payload
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface,count=5)
                        else:
                            scapy.send(command,iface=sending_out_iface,count=5,verbose=False)
                                
                    target.sender = types.MethodType(sender,target)        
                sender_patch(message)
                
                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[3].split(":")[1]): # If there are ICMP packets in pcap.
                            for packet in capture:
                                if packet.haslayer("Raw") and (data in packet["Raw"].fields["load"].decode()): # If there are Raw layer in packet and contains the key message in data.
                                    checks.append(True)
                            
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)
                
                messages.append(message)
                
            elif title == "ICMPv6_Ping_of_death": # ICMPv6 Ping of death
                message.set_title(title)
                message.set_mode_flag('TST')
                message.set_inconclusive (False)
                message.set_data('xxxxxxx')
                message.set_filt("ip6 src host " + sending_out_ip6 + " and ip6 dst host " + listening_in_ip6)
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                        fid=random.randint(0,100000)
                        I=scapy.IPv6(dst=listening_in_ip6, nh=44)
                        ICMP=scapy.ICMPv6EchoRequest(data='x'*104, cksum=0xea9c)
                        FH1=scapy.IPv6ExtHdrFragment(nh=0x3a, offset=0,m=1,id=fid)
                        packet1 = I/FH1/ICMP
                        FH2=scapy.IPv6ExtHdrFragment(nh=0x3a,offset=13,m=0,id=fid)
                        packet2 = I/FH2/data
                        
                        command = []
                        for _ in range(5):
                            command.append(packet1)
                            command.append(packet2)
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                                
                    target.sender = types.MethodType(sender,target) 
                sender_patch(message)
                
                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                        
                        if int(str(capture).split(" ")[4].split(":")[1].replace(">","")): # If it is a ICMPv6 message...
                            for packet in capture:
                                if packet.haslayer("Raw") and (data in str(packet["Raw"].fields["load"])):
                                    checks.append(True)
                                    
                                elif packet.haslayer("ICMPv6EchoRequest") and (data in str(packet["ICMPv6EchoRequest"].fields["data"])):
                                    checks.append(True)
                            
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)
                
                messages.append(message)
                
            elif title == "TCP_NULL_IPv4": # TCP NULL IPv4
                message.set_title(title)
                message.set_mode_flag('TST')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_ports(['8001','8002','8003','8004','8005']) 
                message.set_filt("less 100 and tcp and dst host " + listening_in_ip4 
                                    + " and (port " + message.ports[0] + " or port " + message.ports[1] + " or port " + message.ports[2] 
                                    + " or port " + message.ports[3] + " or port " + message.ports[4] + ")")
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                
                        ports = [int(x) for x in ports]
                        
                        command = scapy.IP(dst=listening_in_ip4)/scapy.TCP(sport=ports,flags="")/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                                
                    target.sender = types.MethodType(sender,target)
                sender_patch(message)
                
                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]): # If there are TCP packets in pcap.
                            for packet in capture: 
                                if packet.haslayer("Raw") and (data in packet["Raw"].fields["load"].decode()): # If there are Raw layer in packet and contains the key message in data.
                                    checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)
                
                messages.append(message)
                
            elif title == "TCP_SYN_FIN_IPv4": # TCP SYN_FIN IPv4
                message.set_title(title)
                message.set_mode_flag('TST')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_ports(['8011','8012','8013','8014','8015']) 
                message.set_filt("less 100 and tcp and dst host " + listening_in_ip4 
                                    + " and (port " + message.ports[0] + " or port " + message.ports[1] + " or port " + message.ports[2] 
                                    + " or port " + message.ports[3] + " or port " + message.ports[4] + ")")
                message.set_data(title)
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                
                        ports = [int(x) for x in ports]
                        
                        command = scapy.IP(dst=listening_in_ip4)/scapy.TCP(sport=ports,flags="SF")/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                                
                    target.sender = types.MethodType(sender,target)
                sender_patch(message)
                
                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]): # If there are TCP packets in pcap.
                            for packet in capture:
                                if (packet["TCP"].fields["flags"].__str__() == "FS") and (data in packet["Raw"].fields["load"].decode()): # If there are 'SYN_FIN' flag  and data in packet
                                    checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)
                
                messages.append(message)
                
            elif title == "TCP_FIN_IPv4": # TCP FIN IPv4
                message.set_title(title)
                message.set_mode_flag('TST')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_ports(['8021','8022','8023','8024','8025']) 
                message.set_filt("less 100 and tcp and dst host " + listening_in_ip4 
                                    + " and (port " + message.ports[0] + " or port " + message.ports[1] + " or port " + message.ports[2] 
                                    + " or port " + message.ports[3] + " or port " + message.ports[4] + ")")
                message.set_data(title)
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                
                        ports = [int(x) for x in ports]
                        
                        command = scapy.IP(dst=listening_in_ip4)/scapy.TCP(sport=ports,flags="F")/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                                        
                    target.sender = types.MethodType(sender,target)
                sender_patch(message)
                
                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]): # If there are TCP packets in pcap.
                            for packet in capture:
                                if (packet["TCP"].fields["flags"].__str__() == "F") and (data in packet["Raw"].fields["load"].decode()): # If there are 'fin' flag  and data in packet
                                    checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)
                
                messages.append(message)
                
            elif title == "TCP_SYN_RST_IPv4": # TCP SYN_RST IPv4
                message.set_title(title)
                message.set_mode_flag('TST')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_ports(['8031','8032','8033','8034','8035']) 
                message.set_filt("less 100 and tcp and dst host " + listening_in_ip4 
                                    + " and (port " + message.ports[0] + " or port " + message.ports[1] + " or port " + message.ports[2] 
                                    + " or port " + message.ports[3] + " or port " + message.ports[4] + ")")
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                        ports = [int(x) for x in ports]
                
                        command = scapy.IP(dst=listening_in_ip4)/scapy.TCP(sport=ports,flags="SR")/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                                        
                    target.sender = types.MethodType(sender,target)
                sender_patch(message)
                
                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]): # If there are TCP packets in pcap.
                            for packet in capture:
                                if (packet["TCP"].fields["flags"].__str__() == "SR") and (data in packet["Raw"].fields["load"].decode()): # If there are 'SYN_RST' flag  and data in packet
                                    checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)
                
                messages.append(message)
                
            elif title == "TCP_NULL_IPv6": # TCP NULL IPv6
                message.set_title(title)
                message.set_mode_flag('TST')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_ports(['8001','8002','8003','8004','8005']) 
                message.set_filt("less 100 and tcp and ip6 dst host " + listening_in_ip6 
                                    + " and (port " + message.ports[0] + " or port " + message.ports[1] + " or port " + message.ports[2] 
                                    + " or port " + message.ports[3] + " or port " + message.ports[4] + ")")
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                        ports = [int(x) for x in ports]
                        
                        command = scapy.IPv6(dst=listening_in_ip6)/scapy.TCP(sport=ports,flags="")/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                                        
                    target.sender = types.MethodType(sender,target)
                sender_patch(message)
                
                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]): # If there are TCP packets in pcap.
                            for packet in capture: 
                                if packet.haslayer("Raw") and (data in packet["Raw"].fields["load"].decode()): # If there are Raw layer in packet and contains the key message in data.
                                    checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)
                
                messages.append(message)
                
            elif title == "TCP_SYN_FIN_IPv6": # TCP SYN_FIN IPv6
                message.set_title(title)
                message.set_mode_flag('TST')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_ports(['8011','8012','8013','8014','8015']) 
                message.set_filt("less 100 and tcp and ip6 dst host " + listening_in_ip6 
                                    + " and (port " + message.ports[0] + " or port " + message.ports[1] + " or port " + message.ports[2] 
                                    + " or port " + message.ports[3] + " or port " + message.ports[4] + ")")
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                
                        ports = [int(x) for x in ports]
                        
                        command = scapy.IPv6(dst=listening_in_ip6)/scapy.TCP(sport=ports,flags="SF")/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                                        
                    target.sender = types.MethodType(sender,target)
                sender_patch(message)
                
                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]): # If there are TCP packets in pcap.
                            for packet in capture:
                                if (packet["TCP"].fields["flags"].__str__() == "FS") and (data in packet["Raw"].fields["load"].decode()): # If there are 'SYN_FIN' flag  and data in packet
                                    checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)
                
                messages.append(message)
                
            elif title == "TCP_FIN_IPv6": # TCP FIN IPv6
                message.set_title(title)
                message.set_mode_flag('TST')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_ports(['8021','8022','8023','8024','8025']) 
                message.set_filt("less 100 and tcp and ip6 dst host " + listening_in_ip6
                                    + " and (port " + message.ports[0] + " or port " + message.ports[1] + " or port " + message.ports[2] 
                                    + " or port " + message.ports[3] + " or port " + message.ports[4] + ")")
                
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                        ports = [int(x) for x in ports]
                        
                        command = scapy.IPv6(dst=listening_in_ip6)/scapy.TCP(sport=ports,flags="F")/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                                        
                    target.sender = types.MethodType(sender,target)
                sender_patch(message)
                
                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]): # If there are TCP packets in pcap.
                            for packet in capture:
                                if (packet["TCP"].fields["flags"].__str__() == "F") and (data in packet["Raw"].fields["load"].decode()): # If there are 'fin' flag  and data in packet
                                    checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)
                
                messages.append(message)
                
            elif title == "TCP_SYN_RST_IPv6": # TCP SYN_RST IPv6
                message.set_title(title)
                message.set_mode_flag('TST')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_ports(['8031','8032','8033','8034','8035']) 
                message.set_filt("less 100 and tcp and ip6 dst host " + listening_in_ip6
                                    + " and (port " + message.ports[0] + " or port " + message.ports[1] + " or port " + message.ports[2] 
                                    + " or port " + message.ports[3] + " or port " + message.ports[4] + ")")
                
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                        ports = [int(x) for x in ports]
                        
                        command = scapy.IPv6(dst=listening_in_ip6)/scapy.TCP(sport=ports,flags="SR")/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                                        
                    target.sender = types.MethodType(sender,target)
                sender_patch(message)
                
                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]): # If there are TCP packets in pcap.
                            for packet in capture:
                                if (packet["TCP"].fields["flags"].__str__() == "SR") and (data in packet["Raw"].fields["load"].decode()): # If there are 'SYN_RST' flag  and data in packet
                                    checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)
                
                messages.append(message)

            elif title == "UDP_Bomb_IPv4": # UDP Bomb IPv4
                message.set_title(title)
                message.set_mode_flag('TST')
                message.set_inconclusive (False)
                message.set_data = ""
                message.set_ports(['8001','8002','8003','8004','8005']) 
                message.set_filt("udp and dst host " + listening_in_ip4
                        + " and (port " + message.ports[0] + " or port " + message.ports[1] + " or port " + message.ports[2] 
                        + " or port " + message.ports[3] + " or port " + message.ports[4] + ")")
                
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                        ports = [int(x) for x in ports]
                        
                        command = scapy.IP(dst=listening_in_ip4)/scapy.UDP(sport=ports,len=65535)
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                                        
                    target.sender = types.MethodType(sender,target)
                sender_patch(message)
                
                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[2].split(":")[1]): # If there are UDP packets in pcap. 
                            checks.append(True)
                            
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)
                
                messages.append(message)
                
            elif title == "UDP_DoS_Chargen_IPv4": # UDP DoS Chargen IPv4
                message.set_title(title)
                message.set_mode_flag('TST')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_filt("udp and dst host " + listening_in_ip4 + " and src port 7 and dst port 19")
                
                
                def sender_patch(target):
                    def sender(target,title,ports,data):  
                        command = scapy.IP(dst=listening_in_ip4)/scapy.UDP(sport=7,dport=19)/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface,count=5)
                        else:
                            scapy.send(command,iface=sending_out_iface,count=5,verbose=False)
                                        
                    target.sender = types.MethodType(sender,target)
                sender_patch(message)
                
                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[2].split(":")[1]): # If there are UDP packets in pcap. 
                            for packet in capture:
                                if packet.haslayer("Raw") and (data in packet["Raw"].fields["load"].decode()): # If there are Raw layer in packet and contains the key message in data.
                                    checks.append(True)
                            
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)
                
                messages.append(message)

            elif title == "UDP_Bomb_IPv6": # UDP Bomb IPv6
                message.set_title(title)
                message.set_mode_flag('TST')
                message.set_inconclusive (False)
                message.set_data = ""
                message.set_ports(['8001','8002','8003','8004','8005']) 
                message.set_filt("udp and ip6 dst host " + listening_in_ip6
                                    + " and (port " + message.ports[0] + " or port " + message.ports[1] + " or port " + message.ports[2] 
                                    + " or port " + message.ports[3] + " or port " + message.ports[4] + ")")
                
                
                def sender_patch(target):
                    def sender(target,title,ports,data): 
                        ports = [int(x) for x in ports]
                        
                        command = scapy.IPv6(dst=listening_in_ip6)/scapy.UDP(sport=ports,len=65535)
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                                        
                    target.sender = types.MethodType(sender,target)     
                sender_patch(message)
                
                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[2].split(":")[1]): # If there are UDP packets in pcap. 
                            checks.append(True)
                            
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)
                
                messages.append(message)
                
            elif title == "UDP_DoS_Chargen_IPv6": # UDP DoS Chargen IPv6
                message.set_title(title)
                message.set_mode_flag('TST')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_filt("udp and ip6 dst host " + listening_in_ip6 + " and src port 7 and dst port 19")
                
                
                def sender_patch(target):
                    def sender(target,title,ports,data): 
                        command = scapy.IPv6(dst=listening_in_ip6)/scapy.UDP(sport=7,dport=19)/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface,count=5)
                        else:
                            scapy.send(command,iface=sending_out_iface,count=5,verbose=False)
                                        
                    target.sender = types.MethodType(sender,target)
                sender_patch(message)
                
                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[2].split(":")[1]): # If there are UDP packets in pcap. 
                            for packet in capture:
                                if packet.haslayer("Raw") and (data in packet["Raw"].fields["load"].decode()): # If there are Raw layer in packet and contains the key message in data.
                                    checks.append(True)
                            
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)
                
                messages.append(message)
                
            elif title == "ICMPv4_flood": # ICMPv4 flood
                message.set_title(title)
                message.set_mode_flag('TST')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_filt("icmp and src host " + sending_out_ip4 + " and dst host " + broadcastip)
                
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                        aux_data = '$'+data+'$'
                        hex_data = aux_data.encode("utf-8").hex()
                        
                        command = "ping -c" + str(flood) + " -I " + sending_out_iface + " -p " + hex_data + " -b " + broadcastip
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color + '\n' + "."*flood + '\n' + "Sent " + str(flood) + " packets.")
                        
                        q = subprocess.run(command.split(" "),stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                        
                    target.sender = types.MethodType(sender,target)    
                sender_patch(message)
                
                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[3].split(":")[1]): # If there are ICMP packets in pcap.
                            for packet in capture:
                                if packet.haslayer("Raw"):
                                    list1 = packet["Raw"].__str__().split("$")
                                    list2 = [data]
                                    if any(item in list1 for item in list2):
                                        checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)
                
                messages.append(message)
                                        
            elif title == "ICMPv6_flood": # ICMPv6 flood
                message.set_title(title)
                message.set_mode_flag('TST')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_filt("icmp6 and ip6 src host " + sending_out_ip6 + " and ip6 dst host " + multicastip6)
                
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                        aux_data = '$'+data+'$'
                        hex_data = aux_data.encode("utf-8").hex()
                        command = "ping -6 -c" + str(flood) + " -I " + sending_out_iface + " -p " + hex_data + " -f " + multicastip6 
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color + '\n' + "."*flood + '\n' + "Sent " + str(flood) + " packets.")
                        
                        q = subprocess.run(command.split(" "),stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                        
                    target.sender = types.MethodType(sender,target)        
                sender_patch(message)
                
                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[4].split(":")[1].replace(">","")): # If it is a ICMPv6 flood message or ICMPv6 Ping message...
                            for packet in capture:
                                if packet.haslayer("ICMPv6EchoRequest"):
                                    list1 = str(packet[0]["ICMPv6EchoRequest"].fields["data"]).split("$")
                                    list2 = [data]
                                    if any(item in list1 for item in list2):
                                        checks.append(True)
                            
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)
                
                messages.append(message)
                
            elif title == "TCP_flood_IPv4": # TCP flood IPv4
                message.set_title(title)
                message.set_mode_flag('TST')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_filt("tcp and dst host " + listening_in_ip4)
                
                
                def sender_patch(target):
                    def sender(target,title,ports,data): 
                        
                        packet = scapy.IP(src=scapy.RandIP(sending_out_ip4 + "/24"), dst=listening_in_ip4)/scapy.TCP(sport=scapy.RandShort(),flags="S")/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(packet,iface=sending_out_iface,count=flood)
                        else:
                            scapy.send(packet,iface=sending_out_iface,count=flood,verbose=False)
                                        
                    target.sender = types.MethodType(sender,target)
                sender_patch(message)
                
                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]): # If there are TCP packets in pcap.
                            for packet in capture:
                                if (packet["TCP"].fields["flags"].__str__() == "S") and (data in packet["Raw"].fields["load"].decode()): # If there are 'syn' flag  and data in packet
                                    checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)
                
                messages.append(message)
                
            elif title == "TCP_flood_IPv6": # TCP flood IPv6
                message.set_title(title)
                message.set_mode_flag('TST')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_filt("tcp and ip6 dst host " + listening_in_ip6)

                    
                def sender_patch(target):
                    def sender(target,title,ports,data): 
                        packet = scapy.IPv6(dst=listening_in_ip6)/scapy.TCP(sport=scapy.RandShort(),flags="S")/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(packet,iface=sending_out_iface,count=flood)
                        else:
                            scapy.send(packet,iface=sending_out_iface,count=flood,verbose=False)
                                        
                    target.sender = types.MethodType(sender,target)
                sender_patch(message)
                
                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]): # If there are TCP packets in pcap.
                            for packet in capture:
                                if (packet["TCP"].fields["flags"].__str__() == "S") and (data in packet["Raw"].fields["load"].decode()): # If there are 'syn' flag  and data in packet
                                    checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)
                
                messages.append(message)
                
            elif title == "IPv4_protocol_scanning": # IPv4 protocol scanning
                message.set_title(title)
                message.set_mode_flag('TST')
                message.set_filt('')
                
                command = "sudo nmap -sO INBOUND_IPv4"
                message.set_inconclusive(True)
                
                def sender_patch(target):
                    def sender(a,b,c,d):
                        pass
                    
                    target.sender = types.MethodType(sender,target)
                sender_patch(message)
                
                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        return False
        
                    target.check = types.MethodType(check,target)
                check_patch(message)
                
                messages.append(message)
                
            elif title == "IPv6_protocol_scanning": # IPv6 protocol scanning
                message.set_title(title)
                message.set_mode_flag('TST')
                message.set_filt('')
                
                command = "sudo nmap -6 -sO IN_BOUND_IPv6"
                message.set_inconclusive(True)
                
                def sender_patch(target):
                    def sender(a,b,c,d):
                        pass
                    
                    target.sender = types.MethodType(sender,target)
                sender_patch(message)

                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        return False
        
                    target.check = types.MethodType(check,target)
                check_patch(message)

                messages.append(message)
            
            elif title == "TCP_port_scanning_IPv4": # TCP port scanning IPv4
                message.set_title(title)
                message.set_mode_flag('TST')
                message.set_filt('')
                
                command = "sudo nmap IN_BOUND_IPv4"
                message.set_inconclusive(True)
                
                def sender_patch(target):
                    def sender(a,b,c,d):
                        pass
                    
                    target.sender = types.MethodType(sender,target)
                sender_patch(message)

                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        return False
        
                    target.check = types.MethodType(check,target)
                check_patch(message)

                messages.append(message)
                
            elif title == "TCP_port_scanning_IPv6": # TCP port scanning IPv6
                message.set_title(title)
                message.set_mode_flag('TST')
                message.set_filt('')
                
                command = "sudo nmap -6 -Pn IN_BOUND_IPv6"
                message.set_inconclusive(True)
                
                def sender_patch(target):
                    def sender(a,b,c,d):
                        pass
                    
                    target.sender = types.MethodType(sender,target)
                sender_patch(message)

                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        return False
        
                    target.check = types.MethodType(check,target)
                check_patch(message)

                messages.append(message)
                
            elif title == "UDP_port_scanning_IPv4": # UDP port scanning IPv4
                message.set_title(title)
                message.set_mode_flag('TST')
                message.set_filt('')
                
                command = "sudo nmap --top-ports 10 -sU IN_BOUND_IPv4"
                message.set_inconclusive(True)
                
                def sender_patch(target):
                    def sender(a,b,c,d):
                        pass
                    
                    target.sender = types.MethodType(sender,target)
                sender_patch(message)

                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        return False
        
                    target.check = types.MethodType(check,target)
                check_patch(message)

                messages.append(message)
                
            elif title == "UDP_port_scanning_IPv6": # UDP port scanning IPv6
                message.set_title(title)
                message.set_mode_flag('TST')
                message.set_filt('')
                
                command = "sudo nmap --top-ports 10 -6 -Pn -sU IN_BOUND_IPv6"
                message.set_inconclusive(True)
                
                def sender_patch(target):
                    def sender(a,b,c,d):
                        pass
                    
                    target.sender = types.MethodType(sender,target)
                sender_patch(message)

                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        return False
        
                    target.check = types.MethodType(check,target)
                check_patch(message)

                messages.append(message)
                
            elif title == "ICMPv4_host_discovery": # ICMPv4 host discovery
                message.set_title(title)
                message.set_mode_flag('TST')
                message.set_filt('')
                
                command = "sudo nmap -sn --disable-arp-ping <IN_BOUND_IPv4/net_mask>"
                message.set_inconclusive(True)
                
                def sender_patch(target):
                    def sender(a,b,c,d):
                        pass
                    
                    target.sender = types.MethodType(sender,target)
                sender_patch(message)

                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        return False
        
                    target.check = types.MethodType(check,target)
                check_patch(message)

                messages.append(message)
                
            elif title == "ICMPv6_host_discovery": # ICMPv6 host discovery
                message.set_title(title)
                message.set_mode_flag('TST')
                message.set_filt('')
                
                command = "sudo nmap -sn --disable-arp-ping -6 fe80::1/64"
                message.set_inconclusive(True)
                
                def sender_patch(target):
                    def sender(a,b,c,d):
                        pass
                    
                    target.sender = types.MethodType(sender,target)
                sender_patch(message)

                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        return False
        
                    target.check = types.MethodType(check,target)
                check_patch(message)

                messages.append(message)
                
            elif title == "LFI_attack": # LFI attack
                message.set_title(title)
                message.set_mode_flag('TST')
                message.set_filt('')
                
                command = ("1.- sudo python3 -m http.server 80" + '\033[1;0m' + '\n' 
                        + '\033[1;37m' + "2.- curl http://IN_BOUNDIPv4" + '\033[1;0m' + '\n' 
                        + '\033[1;37m' + "3.- curl http://IN_BOUND_IPv4/etc/passwd")
                message.set_inconclusive(True)
                
                def sender_patch(target):
                    def sender(a,b,c,d):
                        pass
                    
                    target.sender = types.MethodType(sender,target)
                sender_patch(message)

                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        return False
        
                    target.check = types.MethodType(check,target)
                check_patch(message)

                messages.append(message)




            ## PT Messages
            elif title == "TCP_Broadcast": # TCP Broadcast
                message.set_title(title)
                message.set_mode_flag('PT')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_ports(['8001','8002','8003','8004','8005']) 
                message.set_filt("less 73 and tcp and src host " + broadcastip + " and dst host " + listening_in_ip4 
                                    + " and (port " + message.ports[0] + " or port " + message.ports[1] + " or port " + message.ports[2] 
                                    + " or port " + message.ports[3] + " or port " + message.ports[4] + ")")
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                        
                        ports = [int(x) for x in ports]
                        command = scapy.IP(src=broadcastip,dst=listening_in_ip4)/scapy.TCP(sport=ports)/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                                        
                    target.sender = types.MethodType(sender,target)
                sender_patch(message)
                
                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]): # If there are TCP packets in pcap.
                            for packet in capture: 
                                if packet.haslayer("Raw") and (data in packet["Raw"].fields["load"].decode()): # If there are Raw layer in packet and contains the key message in data.
                                    checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)
                
                messages.append(message)
                
            elif title == "TCP_Universal_Broadcast": # TCP Universal Broadcast
                message.set_title(title)
                message.set_mode_flag('PT')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_ports(['8001','8002','8003','8004','8005']) 
                message.set_filt("less 83 and tcp and src host 255.255.255.255 and dst host " + listening_in_ip4 
                                    + " and (port " + message.ports[0] + " or port " + message.ports[1] + " or port " + message.ports[2] 
                                    + " or port " + message.ports[3] + " or port " + message.ports[4] + ")")
                
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                        ports = [int(x) for x in ports]
                        command = scapy.IP(src='255.255.255.255',dst=listening_in_ip4)/scapy.TCP(sport=ports)/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                                        
                    target.sender = types.MethodType(sender,target)
                sender_patch(message)
                
                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]): # If there are TCP packets in pcap.
                            for packet in capture: 
                                if packet.haslayer("Raw") and (data in packet["Raw"].fields["load"].decode()): # If there are Raw layer in packet and contains the key message in data.
                                    checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)
                
                messages.append(message)
                
            elif title == "TCP_Multicast_IPv4": # TCP Multicast IPv4
                message.set_title(title)
                message.set_mode_flag('PT')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_ports(['8001','8002','8003','8004','8005']) 
                message.set_filt("less 78 and tcp and src host " + multicastip4 + " and dst host " + listening_in_ip4 
                                    + " and (port " + message.ports[0] + " or port " + message.ports[1] + " or port " + message.ports[2] 
                                    + " or port " + message.ports[3] + " or port " + message.ports[4] + ")")
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                        ports = [int(x) for x in ports]
                        command = scapy.IP(src=multicastip4,dst=listening_in_ip4)/scapy.TCP(sport=ports)/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                                        
                    target.sender = types.MethodType(sender,target)
                sender_patch(message)
                
                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]): # If there are TCP packets in pcap.
                            for packet in capture: 
                                if packet.haslayer("Raw") and (data in packet["Raw"].fields["load"].decode()): # If there are Raw layer in packet and contains the key message in data.
                                    checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)
                
                messages.append(message)                    
            
            elif title == "TCP_Multicast_IPv6": # TCP Multicast IPv6
                message.set_title(title)
                message.set_mode_flag('PT')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_ports(['8001','8002','8003','8004','8005'])
                message.set_filt("less 98 and tcp and ip6 src host " + multicastip6 + " and ip6 dst host " + listening_in_ip6
                                    + " and (port " + message.ports[0] + " or port " + message.ports[1] + " or port " + message.ports[2] 
                                    + " or port " + message.ports[3] + " or port " + message.ports[4] + ")")

                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                        ports = [int(x) for x in ports]
                        command =scapy.IPv6(src=multicastip6,dst=listening_in_ip6)/scapy.TCP(sport=ports)/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                                        
                    target.sender = types.MethodType(sender,target)
                sender_patch(message)
                
                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]): # If there are TCP packets in pcap.
                            for packet in capture: 
                                if packet.haslayer("Raw") and (data in packet["Raw"].fields["load"].decode()): # If there are Raw layer in packet and contains the key message in data.
                                    checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)
                
                messages.append(message)
                
            elif title == "TCP_Loopback_IPv4": # TCP Loopback IPv4
                message.set_title(title)
                message.set_mode_flag('PT')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_ports(['8001','8002','8003','8004','8005']) 
                message.set_filt("less 77 and tcp and src host " + loopbackip4 + " and dst host " + listening_in_ip4 
                                    + " and (port " + message.ports[0] + " or port " + message.ports[1] + " or port " + message.ports[2] 
                                    + " or port " + message.ports[3] + " or port " + message.ports[4] + ")")
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                        ports = [int(x) for x in ports]
                        command = scapy.IP(src=loopbackip4,dst=listening_in_ip4)/scapy.TCP(sport=ports)/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                                        
                    target.sender = types.MethodType(sender,target)        
                sender_patch(message)

                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]): # If there are TCP packets in pcap.
                            for packet in capture: 
                                if packet.haslayer("Raw") and (data in packet["Raw"].fields["load"].decode()): # If there are Raw layer in packet and contains the key message in data.
                                    checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)

                messages.append(message)
                
            elif title == "TCP_Loopback_IPv6": # TCP Loopback IPv6
                message.set_title(title)
                message.set_mode_flag('PT')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_ports(['8001','8002','8003','8004','8005']) 
                message.set_filt("less 97 and tcp and ip6 src host " + loopbackip6 + " and ip6 dst host " + listening_in_ip6 
                                    + " and (port " + message.ports[0] + " or port " + message.ports[1] + " or port " + message.ports[2] 
                                    + " or port " + message.ports[3] + " or port " + message.ports[4] + ")")
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                        ports = [int(x) for x in ports]
                        command =scapy.IPv6(src=loopbackip6,dst=listening_in_ip6)/scapy.TCP(sport=ports)/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                                        
                    target.sender = types.MethodType(sender,target)        
                sender_patch(message)

                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]): # If there are TCP packets in pcap.
                            for packet in capture: 
                                if packet.haslayer("Raw") and (data in packet["Raw"].fields["load"].decode()): # If there are Raw layer in packet and contains the key message in data.
                                    checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)

                messages.append(message)

            elif title == "TCP_Unspecified_IPv4": # TCP Unspecified IPv4
                message.set_title(title)
                message.set_mode_flag('PT')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_ports(['8001','8002','8003','8004','8005'])
                message.set_filt("less 80 and tcp and src host 0.0.0.0 and dst host " + listening_in_ip4 
                                    + " and (port " + message.ports[0] + " or port " + message.ports[1] + " or port " + message.ports[2] 
                                    + " or port " + message.ports[3] + " or port " + message.ports[4] + ")")
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                        ports = [int(x) for x in ports]
                        command = scapy.IP(src='0.0.0.0',dst=listening_in_ip4)/scapy.TCP(sport=ports)/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                                        
                    target.sender = types.MethodType(sender,target)        
                sender_patch(message)

                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]): # If there are TCP packets in pcap.
                            for packet in capture: # Other TCP messages.
                                if packet.haslayer("Raw") and (data in packet["Raw"].fields["load"].decode()): # If there are Raw layer in packet and contains the key message in data.
                                    checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)

                messages.append(message)

            elif title == "TCP_Unspecified_IPv6": # TCP Unspecified IPv6
                message.set_title(title)
                message.set_mode_flag('PT')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_ports(['8001','8002','8003','8004','8005']) 
                message.set_filt("less 100 and tcp and ip6 src host :: and ip6 dst host " + listening_in_ip6 
                                    + " and (port " + message.ports[0] + " or port " + message.ports[1] + " or port " + message.ports[2] 
                                    + " or port " + message.ports[3] + " or port " + message.ports[4] + ")")
                
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                        ports = [int(x) for x in ports]
                        command =scapy.IPv6(src='::',dst=listening_in_ip6)/scapy.TCP(sport=ports)/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                                        
                    target.sender = types.MethodType(sender,target)        
                sender_patch(message)

                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]): # If there are TCP packets in pcap.
                            for packet in capture: # Other TCP messages.
                                if packet.haslayer("Raw") and (data in packet["Raw"].fields["load"].decode()): # If there are Raw layer in packet and contains the key message in data.
                                    checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)

                messages.append(message)
                        
            elif title == "TCP_Source_Routing": # TCP Source Routing - IPOption_LSRR()
                message.set_title(title)
                message.set_mode_flag('PT')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_ports(['9001','9002','9003','9004','9005'])
                message.set_filt("less 82 and tcp and src host " + sending_out_ip4 + " and dst host " + listening_in_ip4 
                                    + " and (port " + message.ports[0] + " or port " + message.ports[1] + " or port " + message.ports[2] 
                                    + " or port " + message.ports[3] + " or port " + message.ports[4] + ")")
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                        ports = [int(x) for x in ports]
                        command = scapy.IP(dst=listening_in_ip4,options=scapy.IPOption_LSRR())/scapy.TCP(sport=ports)/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                                        
                    target.sender = types.MethodType(sender,target)        
                sender_patch(message)

                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]): # If there are TCP packets in pcap.
                            for packet in capture: # Other TCP messages.
                                if packet.haslayer("Raw") and (data in packet["Raw"].fields["load"].decode()): # If there are Raw layer in packet and contains the key message in data.
                                    checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)

                messages.append(message)
                        
            elif title == "TCP_Strict_Source_Routing": # TCP Strict Source Routing - IPOption_SSRR()
                message.set_title(title)
                message.set_mode_flag('PT')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_ports(['8101','8102','8103','8104','8105'])
                message.set_filt("less 89 and tcp and src host " + sending_out_ip4 + " and dst host " + listening_in_ip4 
                                    + " and (port " + message.ports[0] + " or port " + message.ports[1] + " or port " + message.ports[2] 
                                    + " or port " + message.ports[3] + " or port " + message.ports[4] + ")")
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                        ports = [int(x) for x in ports]
                        command = scapy.IP(dst=listening_in_ip4,options=scapy.IPOption_SSRR())/scapy.TCP(sport=ports)/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                                        
                    target.sender = types.MethodType(sender,target)        
                sender_patch(message)

                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]): # If there are TCP packets in pcap.
                            for packet in capture: # Other TCP messages.
                                if packet.haslayer("Raw") and (data in packet["Raw"].fields["load"].decode()): # If there are Raw layer in packet and contains the key message in data.
                                    checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)

                messages.append(message)

            elif title == "TCP_Record_Route": # TCP Record Route - IPOption_RR()
                message.set_title(title)
                message.set_mode_flag('PT')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_ports(['8201','8202','8203','8204','8205'])
                message.set_filt("less 80 and tcp and src host " + sending_out_ip4 + " and dst host " + listening_in_ip4 
                                    + " and (port " + message.ports[0] + " or port " + message.ports[1] + " or port " + message.ports[2] 
                                    + " or port " + message.ports[3] + " or port " + message.ports[4] + ")")
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                        ports = [int(x) for x in ports]
                        command = scapy.IP(dst=listening_in_ip4,options=scapy.IPOption_RR())/scapy.TCP(sport=ports)/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                                        
                    target.sender = types.MethodType(sender,target)        
                sender_patch(message)

                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]): # If there are TCP packets in pcap.
                            for packet in capture: # Other TCP messages.
                                if packet.haslayer("Raw") and (data in packet["Raw"].fields["load"].decode()): # If there are Raw layer in packet and contains the key message in data.
                                    checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)

                messages.append(message)
                        
            elif title == "TCP_Timestamp": # TCP Timestamp - IPOption_Timestamp()
                message.set_title(title)
                message.set_mode_flag('PT')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_ports(['8301','8302','8303','8304','8305'])
                message.set_filt("less 85 and tcp and src host " + sending_out_ip4 + " and dst host " + listening_in_ip4 
                                    + " and (port " + message.ports[0] + " or port " + message.ports[1] + " or port " + message.ports[2] 
                                    + " or port " + message.ports[3] + " or port " + message.ports[4] + ")")
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                        ports = [int(x) for x in ports]
                        command = scapy.IP(dst=listening_in_ip4,options=scapy.IPOption_Timestamp())/scapy.TCP(sport=ports)/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                                        
                    target.sender = types.MethodType(sender,target)        
                sender_patch(message)

                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]): # If there are TCP packets in pcap.
                            for packet in capture: # Other TCP messages.
                                if packet.haslayer("Raw") and (data in packet["Raw"].fields["load"].decode()): # If there are Raw layer in packet and contains the key message in data.
                                    checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)

                messages.append(message)

            elif title == "TCP_Security": # TCP Security - IPOption_Security()
                message.set_title(title)
                message.set_mode_flag('PT')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_ports(['8401','8402','8403','8404','8405'])
                message.set_filt("less 100 and tcp and src host " + sending_out_ip4 + " and dst host " + listening_in_ip4 
                                    + " and (port " + message.ports[0] + " or port " + message.ports[1] + " or port " + message.ports[2] 
                                    + " or port " + message.ports[3] + " or port " + message.ports[4] + ")")
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                        ports = [int(x) for x in ports]
                        command = scapy.IP(dst=listening_in_ip4,options=scapy.IPOption_Security())/scapy.TCP(sport=ports)/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                                        
                    target.sender = types.MethodType(sender,target)        
                sender_patch(message)

                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]): # If there are TCP packets in pcap.
                            for packet in capture: # Other TCP messages.
                                if packet.haslayer("Raw") and (data in packet["Raw"].fields["load"].decode()): # If there are Raw layer in packet and contains the key message in data.
                                    checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)

                messages.append(message)

            elif title == "TCP_Malformed": # TCP Malformed message
                message.set_title(title)
                message.set_mode_flag('PT')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_ports(['8501','8502','8503','8504','8505'])
                message.set_filt("less 100 and tcp and src host " + sending_out_ip4 + " and dst host " + listening_in_ip4 
                                    + " and (port " + message.ports[0] + " or port " + message.ports[1] + " or port " + message.ports[2] 
                                    + " or port " + message.ports[3] + " or port " + message.ports[4] + ")")
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                        ports = [int(x) for x in ports]
                        command = scapy.IP(dst=listening_in_ip4,options=scapy.IPOption(b'\x02'))/scapy.TCP(sport=ports)/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                                        
                    target.sender = types.MethodType(sender,target)        
                sender_patch(message)

                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]): # If there are TCP packets in pcap.
                            for packet in capture: # Other TCP messages.
                                if packet.haslayer("Raw") and (data in packet["Raw"].fields["load"].decode()): # If there are Raw layer in packet and contains the key message in data.
                                    checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)

                messages.append(message)

            elif title == "TCP_Incomplete_1": # TCP Incomplete message 1
                message.set_title(title)
                message.set_mode_flag('PT')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_ports(['8601','8602','8603','8604','8605'])
                message.set_filt("less 100 and tcp and src host " + sending_out_ip4 + " and dst host " + listening_in_ip4 
                                    + " and (port " + message.ports[0] + " or port " + message.ports[1] + " or port " + message.ports[2] 
                                    + " or port " + message.ports[3] + " or port " + message.ports[4] + ")")
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                        ports = [int(x) for x in ports]
                        command = scapy.IP(dst=listening_in_ip4,options=scapy.IPOption())/scapy.TCP(sport=ports)/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
        
                    target.sender = types.MethodType(sender,target)
                sender_patch(message)
                
                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]): # If there are TCP packets in pcap.
                            for packet in capture:
                                if packet.haslayer("Raw") and (b'\x02\x00\x00' in packet["Raw"].fields["load"]): # If there are Raw layer in packet and contains the key message in data.
                                    checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)
                
                messages.append(message)
                    
            elif title == "TCP_Incomplete_2": # TCP Incomplete message 2
                message.set_title(title)
                message.set_mode_flag('PT')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_ports(['8701','8702','8703','8704','8705'])
                message.set_filt("less 100 and tcp and src host " + sending_out_ip4 + " and dst host " + listening_in_ip4 
                                    + " and (port " + message.ports[0] + " or port " + message.ports[1] + " or port " + message.ports[2] 
                                    + " or port " + message.ports[3] + " or port " + message.ports[4] + ")")
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                        ports = [int(x) for x in ports]
                        command = scapy.IP(dst=listening_in_ip4,options=scapy.IPOption(option=2))/scapy.TCP(sport=ports)/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                                        
                    target.sender = types.MethodType(sender,target)        
                sender_patch(message)

                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]): # If there are TCP packets in pcap.
                            for packet in capture: # Other TCP messages.
                                if packet.haslayer("Raw") and (data in packet["Raw"].fields["load"].decode()): # If there are Raw layer in packet and contains the key message in data.
                                    checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)

                messages.append(message)

            elif title == "TCP_Extended_Security": # TCP Extended Security
                message.set_title(title)
                message.set_mode_flag('PT')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_ports(['8801','8802','8803','8804','8805'])
                message.set_filt("less 100 and tcp and src host " + sending_out_ip4 + " and dst host " + listening_in_ip4 
                                    + " and (port " + message.ports[0] + " or port " + message.ports[1] + " or port " + message.ports[2] 
                                    + " or port " + message.ports[3] + " or port " + message.ports[4] + ")")        
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                        ports = [int(x) for x in ports]
                        command = scapy.IP(dst=listening_in_ip4,options=scapy.IPOption_Security(option="extended_security"))/scapy.TCP(sport=ports)/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                                        
                    target.sender = types.MethodType(sender,target)        
                sender_patch(message)

                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]): # If there are TCP packets in pcap.
                            for packet in capture: # Other TCP messages.
                                if packet.haslayer("Raw") and (data in packet["Raw"].fields["load"].decode()): # If there are Raw layer in packet and contains the key message in data.
                                    checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)

                messages.append(message)

            elif title == "TCP_Commercial_Security": # TCP Commercial_Security
                message.set_title(title)
                message.set_mode_flag('PT')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_ports(['8901','8902','8903','8904','8905'])
                message.set_filt("less 100 and tcp and src host " + sending_out_ip4 + " and dst host " + listening_in_ip4 
                                    + " and (port " + message.ports[0] + " or port " + message.ports[1] + " or port " + message.ports[2] 
                                    + " or port " + message.ports[3] + " or port " + message.ports[4] + ")")
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                        ports = [int(x) for x in ports]
                        command = scapy.IP(dst=listening_in_ip4,options=scapy.IPOption_Security(option="commercial_security"))/scapy.TCP(sport=ports)/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                                        
                    target.sender = types.MethodType(sender,target)        
                sender_patch(message)

                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]): # If there are TCP packets in pcap.
                            for packet in capture: # Other TCP messages.
                                if packet.haslayer("Raw") and (data in packet["Raw"].fields["load"].decode()): # If there are Raw layer in packet and contains the key message in data.
                                    checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)

                messages.append(message)

            elif title == "TCP_Link_Local_source_IPv4": # TCP Link-Local source IPv4
                message.set_title(title)
                message.set_mode_flag('PT')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_ports(['8001','8002','8003','8004','8005'])
                message.set_filt("less 100 and tcp and dst host " + listening_in_ip4 + " and src host " + localip4 
                                    + " and (port " + message.ports[0] + " or port " + message.ports[1] + " or port " + message.ports[2] 
                                    + " or port " + message.ports[3] + " or port " + message.ports[4] + ")")
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                        ports = [int(x) for x in ports]
                        command = scapy.IP(src=localip4,dst=listening_in_ip4)/scapy.TCP(sport=ports)/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                                        
                    target.sender = types.MethodType(sender,target)        
                sender_patch(message)

                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]): # If there are TCP packets in pcap.
                            for packet in capture: # Other TCP messages.
                                if packet.haslayer("Raw") and (data in packet["Raw"].fields["load"].decode()): # If there are Raw layer in packet and contains the key message in data.
                                    checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)

                messages.append(message)

            elif title == "TCP_Link_Local_source_IPv6": # TCP Link-Local source IPv6
                message.set_title(title)
                message.set_mode_flag('PT')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_ports(['8001','8002','8003','8004','8005'])
                message.set_filt("less 100 and tcp and ip6 dst host " + listening_in_ip6 + " and ip6 src host " + localip6 
                                    + " and (port " + message.ports[0] + " or port " + message.ports[1] + " or port " + message.ports[2] 
                                    + " or port " + message.ports[3] + " or port " + message.ports[4] + ")")
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                        ports = [int(x) for x in ports]
                        command =scapy.IPv6(src=localip6,dst=listening_in_ip6)/scapy.TCP(sport=ports)/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                                        
                    target.sender = types.MethodType(sender,target)        
                sender_patch(message)

                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]): # If there are TCP packets in pcap.
                            for packet in capture: # Other TCP messages.
                                if packet.haslayer("Raw") and (data in packet["Raw"].fields["load"].decode()): # If there are Raw layer in packet and contains the key message in data.
                                    checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)

                messages.append(message)

            elif title == "TCP_Link_Local_destination_IPv4": # TCP Link-Local destination IPv4
                message.set_title(title)
                message.set_mode_flag('PT')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_ports(['8001','8002','8003','8004','8005'])
                message.set_filt("less 100 and tcp and dst host " + localip4 + " and src host " + sending_out_ip4 
                                    + " and (port " + message.ports[0] + " or port " + message.ports[1] + " or port " + message.ports[2] 
                                    + " or port " + message.ports[3] + " or port " + message.ports[4] + ")")
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                        ports = [int(x) for x in ports]
                        command = scapy.IP(src=sending_out_ip4,dst=localip4)/scapy.TCP(sport=ports)/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                                        
                    target.sender = types.MethodType(sender,target)        
                sender_patch(message)

                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]): # If there are TCP packets in pcap.
                            for packet in capture: # Other TCP messages.
                                if packet.haslayer("Raw") and (data in packet["Raw"].fields["load"].decode()): # If there are Raw layer in packet and contains the key message in data.
                                    checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)

                messages.append(message)

            elif title == "TCP_Link_Local_destination_IPv6": # TCP Link-Local destination IPv6
                message.set_title(title)
                message.set_mode_flag('PT')
                message.set_inconclusive (False)
                message.set_data(title)
                message.set_ports(['8001','8002','8003','8004','8005'])
                message.set_filt("less 110 and tcp and ip6 dst host " + localip6 + " and ip6 src host " + sending_out_ip6
                                    + " and (port " + message.ports[0] + " or port " + message.ports[1] + " or port " + message.ports[2] 
                                    + " or port " + message.ports[3] + " or port " + message.ports[4] + ")")
                
                def sender_patch(target):
                    def sender(target,title,ports,data):
                        ports = [int(x) for x in ports]
                        command =scapy.IPv6(src=sending_out_ip6,dst=localip6)/scapy.TCP(sport=ports)/data
                        
                        scapy.conf.iface = sending_out_iface
                        if verbose:
                            print("Sending: " + purple + title + " message" + reset_color)
                            scapy.send(command,iface=sending_out_iface)
                        else:
                            scapy.send(command,iface=sending_out_iface,verbose=False)
                                        
                    target.sender = types.MethodType(sender,target)        
                sender_patch(message)

                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        checks = []
                        if verbose:
                            capture = scapy.sniff(offline=path,filter=filt) 
                        else:
                            capture = scapy.sniff(offline=path,filter=filt,quiet=True) 
                            
                        if int(str(capture).split(" ")[1].split(":")[1]): # If there are TCP packets in pcap.
                            for packet in capture: # Other TCP messages.
                                if packet.haslayer("Raw") and (data in packet["Raw"].fields["load"].decode()): # If there are Raw layer in packet and contains the key message in data.
                                    checks.append(True)
                        
                        return checks
        
                    target.check = types.MethodType(check,target)
                check_patch(message)

                messages.append(message)

            elif title == "TCP_port_scanning_with_CONNECT": # TCP port scanning with CONNECT
                message.set_title(title)
                message.set_mode_flag('PT')
                message.set_filt('')
                
                command = "sudo nmap -sT IN_BOUND_IPv4 --reason"
                message.set_inconclusive(True)
                
                def sender_patch(target):
                    def sender(a,b,c,d):
                        pass
                    
                    target.sender = types.MethodType(sender,target)
                sender_patch(message)

                def check_patch(target):
                    def check(target,path,filt,data,verbose):
                        return False
        
                    target.check = types.MethodType(check,target)
                check_patch(message)

                messages.append(message)
                

    return  messages


 
# NET_INFO
#-----------------------------------------------------------------------------------
def net_info(destination_ip4,interface):
    """message_manager function:
        * Operation: if an interface is specified, extracts the IPv4 
                and IPv6 addresses related to that interface from an IP 
                of the destination host. Else, extracts the interface related 
                to that IPv4.
        * Method used by the following methods: -
        * Use the following methods: -
        * Libraries needed: subprocess.
        
        * Input arguments:
            -destination_ip4: target host IPv4. <String type>.
            -interface: target host interface. <String type>.
        
        * Output arguments: 
            -ipv4: IPv4 addres related to the given interface. <String type>.
            -ipv6: IPv6 addres related to the given interface. <String type>.
            -iface: interface related to the given IPv4 address. <String type>.
    """
    
    if interface == '_':
        in_netinfo_command = "ssh root@{} ip -br a | grep {}".format(destination_ip4,destination_ip4) + " | awk '{print $1}'"
        in_netinfo_conn = subprocess.run(in_netinfo_command,shell=True,universal_newlines=True,stdout=subprocess.PIPE)
        iface = in_netinfo_conn.stdout.rstrip()
        
        return iface
        
    else:
        in_netinfo_command = "ssh root@{} ip -br a | grep {}".format(destination_ip4,interface) + " | awk '{print $3,$4}'"
        in_netinfo_conn = subprocess.run(in_netinfo_command,shell=True,universal_newlines=True,stdout=subprocess.PIPE)
        in_raw_netinfo = in_netinfo_conn.stdout.split(" ")
        ip4 = in_raw_netinfo[0].split("/")[0]
        ip6 = in_raw_netinfo[1].split("/")[0]
                    
        return ip4,ip6
 
 
 
# HIDE_CURSOR AND SHOW_CURSOR
#------------------------------------------------------------------------------------
def hide_cursor():
    """message_manager function:
        * Operation: hide the cursor. 
        * Method used by the following methods: -
        * Use the following methods: -
        * Libraries needed: scapy.
        
        * Input arguments: -
        
        * Output arguments: -
    """
    sys.stdout.write("\033[?25l")
    sys.stdout.flush()

def show_cursor():
    """message_manager function:
        * Operation: hide the cursor. 
        * Method used by the following methods: -
        * Use the following methods: -
        * Libraries needed: scapy.
        
        * Input arguments: -
        
        * Output arguments: -
    """
    sys.stdout.write("\033[?25h")
    sys.stdout.flush()
  
  

# TST TABLE
#------------------------------------------------------------------------------------  
class TST_table:
    """TST_Table CLASS:
    
        * Operation: generate the tst_table.
        * Method used by the following methods: table_configuration.
        * Use the following methods: -.
        * Use the following clases: -.
        * Libraries needed: -.
    """
    
    def __init__(self):
        
        self.reset_color = '\033[1;0m'
        self.test_pass = '\033[1;32m' + "PASS" + '\033[1;0m'
        self.test_fail = '\033[1;31m' + "FAIL" + '\033[1;0m'
        self.test_skip = '\033[1;35m' + "SKIP" + '\033[1;0m' 
        self.inconclusive = '\033[1;35m' + "INCONCLUSIVE:" + '\033[1;0m'
        self.h_line = chr(9472) 
        self.v_line = chr(9474)
        self.t_l_corner = chr(9484)
        self.t_r_corner = chr(9488) 
        self.b_l_corner = chr(9492)
        self.b_r_corner = chr(9496)
        self.l_end = chr(9500)
        self.r_end = chr(9508)
        self.t_end = chr(9516) 
        self.b_end = chr(9524)
        self.cross = chr(9532)
        
        self.ipv4_fragment_overlap = ''
        self.ipv6_fragment_overlap = ''
        self.tcp_same_dst_and_src_ipv4 = ''
        self.tcp_same_dst_and_src_ipv6 = ''
        self.icmpv4_ping_of_death = ''
        self.icmpv6_ping_of_death = ''
        self.tcp_null_ipv4 = ''
        self.tcp_null_ipv6 = ''
        self.tcp_syn_fin_ipv4 = ''
        self.tcp_syn_fin_ipv6 = ''
        self.tcp_fin_ipv4 = ''
        self.tcp_fin_ipv6 = ''
        self.tcp_syn_rst_ipv4 = ''
        self.tcp_syn_rst_ipv6 = ''
        self.udp_bomb_ipv4 = ''
        self.udp_bomb_ipv6 = ''
        self.udp_dos_chargen_ipv4 = ''
        self.udp_dos_chargen_ipv6 = ''
        self.icmpv4_flood = ''
        self.icmpv6_flood = ''
        self.tcp_flood_ipv4 = ''
        self.tcp_flood_ipv6 = ''
        
        self.tst_table = []
        
        
    def set_ipv4_fragment_overlap(self,check,run):
        if run:
            if check:
                self.ipv4_fragment_overlap = self.test_fail
            else:
                self.ipv4_fragment_overlap = self.test_pass
        else:
            self.ipv4_fragment_overlap = self.test_skip
        
    def set_ipv6_fragment_overlap(self,check,run):
        if run:
            if check:
                self.ipv6_fragment_overlap = self.test_fail
            else:
                self.ipv6_fragment_overlap = self.test_pass
        else:
            self.ipv6_fragment_overlap = self.test_skip
        
    def set_tcp_same_dst_and_src_ipv4(self,check,run):
        if run:
            if check:
                self.tcp_same_dst_and_src_ipv4 = self.test_fail
            else:
                self.tcp_same_dst_and_src_ipv4 = self.test_pass
        else:
            self.tcp_same_dst_and_src_ipv4 = self.test_skip
            
    def set_tcp_same_dst_and_src_ipv6(self,check,run):
        if run:
            if check:
                self.tcp_same_dst_and_src_ipv6 = self.test_fail
            else:
                self.tcp_same_dst_and_src_ipv6 = self.test_pass
        else:
            self.tcp_same_dst_and_src_ipv6 = self.test_skip
            
    def set_icmpv4_ping_of_death(self,check,run):
        if run:
            if check:
                self.icmpv4_ping_of_death = self.test_fail
            else:
                self.icmpv4_ping_of_death = self.test_pass
        else:
            self.icmpv4_ping_of_death = self.test_skip
            
    def set_icmpv6_ping_of_death(self,check,run):
        if run:
            if check:
                self.icmpv6_ping_of_death = self.test_fail
            else:
                self.icmpv6_ping_of_death = self.test_pass
        else:
            self.icmpv6_ping_of_death = self.test_skip
            
    def set_tcp_null_ipv4(self,check,run):
        if run:
            if check:
                self.tcp_null_ipv4 = self.test_fail
            else:
                self.tcp_null_ipv4 = self.test_pass
        else:
            self.tcp_null_ipv4 = self.test_skip
            
    def set_tcp_null_ipv6(self,check,run):
        if run:
            if check:
                self.tcp_null_ipv6 = self.test_fail
            else:
                self.tcp_null_ipv6 = self.test_pass
        else:
            self.tcp_null_ipv6 = self.test_skip
            
    def set_tcp_syn_fin_ipv4(self,check,run):
        if run:
            if check:
                self.tcp_syn_fin_ipv4 = self.test_fail
            else:
                self.tcp_syn_fin_ipv4 = self.test_pass
        else:
            self.tcp_syn_fin_ipv4 = self.test_skip
            
    def set_tcp_syn_fin_ipv6(self,check,run):
        if run:
            if check:
                self.tcp_syn_fin_ipv6 = self.test_fail
            else:
                self.tcp_syn_fin_ipv6 = self.test_pass
        else:
            self.tcp_syn_fin_ipv6 = self.test_skip
            
    def set_tcp_fin_ipv4(self,check,run):
        if run:
            if check:
                self.tcp_fin_ipv4 = self.test_fail
            else:
                self.tcp_fin_ipv4 = self.test_pass
        else:
            self.tcp_fin_ipv4 = self.test_skip

    def set_tcp_fin_ipv6(self,check,run):
        if run:
            if check:
                self.tcp_fin_ipv6 = self.test_fail
            else:
                self.tcp_fin_ipv6 = self.test_pass
        else:
            self.tcp_fin_ipv6 = self.test_skip
            
    def set_tcp_syn_rst_ipv4(self,check,run):
        if run:
            if check:
                self.tcp_syn_rst_ipv4 = self.test_fail
            else:
                self.tcp_syn_rst_ipv4 = self.test_pass
        else:
            self.tcp_syn_rst_ipv4 = self.test_skip
            
    def set_tcp_syn_rst_ipv6(self,check,run):
        if run:
            if check:
                self.tcp_syn_rst_ipv6 = self.test_fail
            else:
                self.tcp_syn_rst_ipv6 = self.test_pass
        else:
            self.tcp_syn_rst_ipv6 = self.test_skip
            
    def set_udp_bomb_ipv4(self,check,run):
        if run:
            if check:
                self.udp_bomb_ipv4 = self.test_fail
            else:
                self.udp_bomb_ipv4 = self.test_pass
        else:
            self.udp_bomb_ipv4 = self.test_skip
            
    def set_udp_bomb_ipv6(self,check,run):
        if run:
            if check:
                self.udp_bomb_ipv6 = self.test_fail
            else:
                self.udp_bomb_ipv6 = self.test_pass
        else:
            self.udp_bomb_ipv6 = self.test_skip
        
    def set_udp_dos_chargen_ipv4(self,check,run):
        if run:
            if check:
                self.udp_dos_chargen_ipv4 = self.test_fail
            else:
                self.udp_dos_chargen_ipv4 = self.test_pass
        else:
            self.udp_dos_chargen_ipv4 = self.test_skip
            
    def set_udp_dos_chargen_ipv6(self,check,run):
        if run:
            if check:
                self.udp_dos_chargen_ipv6 = self.test_fail
            else:
                self.udp_dos_chargen_ipv6 = self.test_pass
        else:
            self.udp_dos_chargen_ipv6 = self.test_skip
            
    def set_icmpv4_flood(self,check,run):
        if run:
            if check:
                self.icmpv4_flood = self.test_fail
            else:
                self.icmpv4_flood = self.test_pass
        else:
            self.icmpv4_flood = self.test_skip
            
    def set_icmpv6_flood(self,check,run):
        if run:
            if check:
                self.icmpv6_flood = self.test_fail
            else:
                self.icmpv6_flood = self.test_pass
        else:
            self.icmpv6_flood = self.test_skip
            
    def set_tcp_flood_ipv4(self,check,run):
        if run:
            if check:
                self.tcp_flood_ipv4 = self.test_fail
            else:
                self.tcp_flood_ipv4 = self.test_pass
        else:
            self.tcp_flood_ipv4 = self.test_skip
            
    def set_tcp_flood_ipv6(self,check,run):
        if run:
            if check:
                self.tcp_flood_ipv6 = self.test_fail
            else:
                self.tcp_flood_ipv6 = self.test_pass
        else:
            self.tcp_flood_ipv6 = self.test_skip
    
      
    
    def set_tst_table(self,in_bound_ipv4,in_bound_ipv6):
        
        end_1 = self.v_line + "\t" + self.v_line + "\t\t" + self.l_end + (self.h_line*20) + self.cross +  (self.h_line*10) + self.cross + (self.h_line*63)+ self.r_end
        end_2 = self.v_line + "\t" + self.l_end  + (self.h_line*15) + self.cross + (self.h_line*20) + self.cross +  (self.h_line*10) + self.cross + (self.h_line*63)+ self.r_end
        
        
        self.tst_table = [
            self.t_l_corner + (self.h_line*119) + self.t_r_corner,
            self.v_line + "\t\t\t\t\t\t\t" + "TST TABLE" + "\t\t\t\t\t\t\t" + self.v_line,      
            self.b_l_corner + (self.h_line*119) + self.b_r_corner,
            self.t_l_corner + (self.h_line*7) + self.t_end + (self.h_line*15) + self.t_end + (self.h_line*20) + self.t_end + (self.h_line*10) + self.t_end + (self.h_line*63) + self.t_r_corner,
            self.v_line + " IDS.7 " + self.v_line + " IP Attacks    " + self.v_line + " Fragment           " + self.v_line +  "   IPv4   " + self.v_line + "\t\t\t\t" + "{}".format(self.ipv4_fragment_overlap) + "\t\t\t\t"+ self.v_line,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + " overlap            " + self.l_end +  (self.h_line*10)  + self.cross + (self.h_line*63) + self.r_end,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + "\t\t     " + self.v_line +  "   IPv6   " + self.v_line + "\t\t\t\t" + "{}".format(self.ipv6_fragment_overlap) + "\t\t\t\t"+ self.v_line,
            self.v_line + "\t" + self.v_line + "\t\t" + self.l_end + (self.h_line*20) + self.cross +  (self.h_line*10) + self.cross + (self.h_line*63)+ self.r_end,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + " Same source        " + self.v_line +  "   IPv4   " + self.v_line + "\t\t\t\t" + "{}".format(self.tcp_same_dst_and_src_ipv4) + "\t\t\t\t" + self.v_line,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + " and destination    " + self.l_end +  (self.h_line*10)  + self.cross + (self.h_line*63) + self.r_end,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + "\t\t     "  + self.v_line +  "   IPv6   " + self.v_line + "\t\t\t\t" + "{}".format(self.tcp_same_dst_and_src_ipv6) + "\t\t\t\t" + self.v_line,
            self.v_line + "\t" + self.l_end  + (self.h_line*15) + self.cross + (self.h_line*20) + self.cross +  (self.h_line*10) + self.cross + (self.h_line*63)+ self.r_end,
            self.v_line + "\t" + self.v_line + " ICMP Attacks  " + self.v_line + " Ping               " + self.v_line +  "   IPv4   " + self.v_line + "\t\t\t\t" + "{}".format(self.icmpv4_ping_of_death) + "\t\t\t\t" + self.v_line,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + " of death           " + self.l_end +  (self.h_line*10)  + self.cross + (self.h_line*63) + self.r_end,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + "\t\t     " + self.v_line +  "   IPv6   " + self.v_line + "\t\t\t\t" + "{}".format(self.icmpv6_ping_of_death) + "\t\t\t\t" + self.v_line,
            end_2,
            self.v_line + "\t" + self.v_line + " TCP Attacks   " + self.v_line + " Flags              " + self.v_line +  "   IPv4   " + self.v_line + "\t\t\t\t" + "{}".format(self.tcp_null_ipv4) + "\t\t\t\t" + self.v_line,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + " TCP NULL           " + self.l_end +  (self.h_line*10)  + self.cross + (self.h_line*63) + self.r_end,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + "\t\t     " + self.v_line +  "   IPv6   " + self.v_line + "\t\t\t\t" + "{}".format(self.tcp_null_ipv6) + "\t\t\t\t" + self.v_line,
            end_1,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + " Flags TCP          " + self.v_line +  "   IPv4   " + self.v_line + "\t\t\t\t" + "{}".format(self.tcp_syn_fin_ipv4) + "\t\t\t\t" + self.v_line,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + " SYN_FIN            " + self.l_end +  (self.h_line*10)  + self.cross + (self.h_line*63) + self.r_end,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + "\t\t     "  + self.v_line +  "   IPv6   " + self.v_line + "\t\t\t\t" + "{}".format(self.tcp_syn_fin_ipv6) + "\t\t\t\t" + self.v_line,
            end_1,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + " Flags only         " + self.v_line +  "   IPv4   " + self.v_line + "\t\t\t\t" + "{}".format(self.tcp_fin_ipv4) + "\t\t\t\t" + self.v_line,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + " TCP FIN            " + self.l_end +  (self.h_line*10)  + self.cross + (self.h_line*63) + self.r_end ,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + "\t\t     "  + self.v_line +  "   IPv6   " + self.v_line + "\t\t\t\t" + "{}".format(self.tcp_fin_ipv6) + "\t\t\t\t" + self.v_line,
            end_1,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + " Flags TCP          " + self.v_line +  "   IPv4   " + self.v_line + "\t\t\t\t" + "{}".format(self.tcp_syn_rst_ipv4) + "\t\t\t\t" + self.v_line,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + " SYN_RST            " + self.l_end +  (self.h_line*10)  + self.cross + (self.h_line*63) + self.r_end,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + "\t\t     "  + self.v_line +  "   IPv6   " + self.v_line + "\t\t\t\t" + "{}".format(self.tcp_syn_rst_ipv6) + "\t\t\t\t" + self.v_line,
            end_2,
            self.v_line + "\t" + self.v_line + " UDP Attacks   " + self.v_line + " UDP Bomb           " + self.v_line +  "   IPv4   " + self.v_line + "\t\t\t\t" + "{}".format(self.udp_bomb_ipv4) + "\t\t\t\t" + self.v_line,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + "\t\t     "  + self.l_end +  (self.h_line*10)  + self.cross + (self.h_line*63) + self.r_end,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + "\t\t     "  + self.v_line +  "   IPv6   " + self.v_line + "\t\t\t\t" + "{}".format(self.udp_bomb_ipv6) + "\t\t\t\t" + self.v_line,
            end_1,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + " UDP DOS            " + self.v_line +  "   IPv4   " + self.v_line + "\t\t\t\t" + "{}".format(self.udp_dos_chargen_ipv4) + "\t\t\t\t" + self.v_line,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + " chargen            "  + self.l_end +  (self.h_line*10)  + self.cross + (self.h_line*63) + self.r_end,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + "\t\t     "  + self.v_line +  "   IPv6   " + self.v_line + "\t\t\t\t" + "{}".format(self.udp_dos_chargen_ipv6) + "\t\t\t\t" + self.v_line,
            self.l_end + (self.h_line*7) + self.cross + (self.h_line*15) + self.cross + (self.h_line*20) + self.cross + (self.h_line*10) + self.cross + (self.h_line*63) + self.r_end,
            self.v_line + " IDS.8 " + self.v_line + " DOS host      " + self.v_line + " ICMP flood         " + self.v_line +  "   IPv4   " + self.v_line + "\t\t\t\t" + "{}".format(self.icmpv4_flood) + "\t\t\t\t" + self.v_line,
            self.v_line + "\t" + self.v_line + " attacks       " + self.v_line + "\t\t     " + self.l_end +  (self.h_line*10) + self.cross + (self.h_line*63)+ self.r_end,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + "\t\t     "  + self.v_line +  "   IPv6   " + self.v_line + "\t\t\t\t" + "{}".format(self.icmpv6_flood) + "\t\t\t\t" + self.v_line,
            end_1,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + " TCP flood          " + self.v_line +  "   IPv4   " + self.v_line + "\t\t\t\t" + "{}".format(self.tcp_flood_ipv4) + "\t\t\t\t" + self.v_line,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + "\t\t     "  + self.l_end +  (self.h_line*10)  + self.cross + (self.h_line*63) + self.r_end,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + "\t\t     "  + self.v_line +  "   IPv6   " + self.v_line + "\t\t\t\t" + "{}".format(self.tcp_flood_ipv6) + "\t\t\t\t" + self.v_line,
            end_2,
            self.v_line + "\t" + self.v_line + " Protocol      " + self.v_line + " IP                 " + self.v_line +  "   IPv4   " + self.v_line + " {} ".format(self.inconclusive) + "\t\t\t\t\t\t" + self.v_line,
            self.v_line + "\t" + self.v_line + " scanning      " + self.v_line + "\t\t     "  + self.v_line +  "          " + self.v_line  + " {} ".format("sudo nmap -sO " + in_bound_ipv4 + " "*(47-len(in_bound_ipv4))) + self.v_line,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + "\t\t     " + self.l_end +  (self.h_line*10) + self.cross + (self.h_line*63)+ self.r_end,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + "\t\t     "  + self.v_line +  "   IPv6   " + self.v_line + " {} ".format(self.inconclusive) + "\t\t\t\t\t\t" + self.v_line,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + "\t\t     "  + self.v_line +  "          " + self.v_line  + " {} ".format("sudo nmap -6 -sO " + in_bound_ipv6 + " "*(44-len(in_bound_ipv6))) + self.v_line,
            end_2,
            self.v_line + "\t" + self.v_line + " Port          " + self.v_line + " TCP                " + self.v_line +  "   IPv4   " + self.v_line + " {} ".format(self.inconclusive) + "\t\t\t\t\t\t" + self.v_line,
            self.v_line + "\t" + self.v_line + " scanning      " + self.v_line + "\t\t     "  + self.v_line +  "          " + self.v_line  + " {} ".format("sudo nmap " + in_bound_ipv4 + " "*(51-len(in_bound_ipv4))) + self.v_line,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + "\t\t     " + self.l_end +  (self.h_line*10) + self.cross + (self.h_line*63)+ self.r_end,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + "\t\t     "  + self.v_line +  "   IPv6   " + self.v_line  + " {} ".format(self.inconclusive) + "\t\t\t\t\t\t" + self.v_line,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + "\t\t     "  + self.v_line +  "          " + self.v_line  + " {} ".format("sudo nmap -6 -Pn " + in_bound_ipv6 + " "*(44-len(in_bound_ipv6))) + self.v_line,
            end_1,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + " UDP                " + self.v_line +  "   IPv4   " + self.v_line + " {} ".format(self.inconclusive) + "\t\t\t\t\t\t" + self.v_line,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + "\t\t     "  + self.v_line +  "          " + self.v_line  + " {} ".format("sudo nmap --top-ports 10 -sU " + in_bound_ipv4 + " "*(32-len(in_bound_ipv4))) + self.v_line,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + "\t\t     "  + self.l_end +  (self.h_line*10)  + self.cross + (self.h_line*63) + self.r_end,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + "\t\t     "  + self.v_line +  "   IPv6   " + self.v_line + " {} ".format(self.inconclusive) + "\t\t\t\t\t\t" + self.v_line,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + "\t\t     "  + self.v_line +  "          " + self.v_line + " {} ".format("sudo nmap --top-ports 10 -6 -Pn -sU " + in_bound_ipv6 + " "*(25-len(in_bound_ipv6))) + self.v_line,
            end_2,
            self.v_line + "\t" + self.v_line + " Host          " + self.v_line + " ICMP               " + self.v_line +  "   IPv4   " + self.v_line + " {}  ".format(self.inconclusive) + "\t\t\t\t\t\t" + self.v_line,
            self.v_line + "\t" + self.v_line + " discovery     " + self.v_line + "\t\t     " + self.v_line +  "          " + self.v_line + " {} ".format("sudo nmap -sn --disable-arp-ping " + in_bound_ipv4 + "/24" + " "*(25-len(in_bound_ipv4))) + self.v_line,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + "\t\t     " + self.l_end +  (self.h_line*10) + self.cross + (self.h_line*63)+ self.r_end,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + "\t\t     "  + self.v_line +  "   IPv6   " + self.v_line + " {}  ".format(self.inconclusive) + "\t\t\t\t\t\t" + self.v_line,
            self.v_line + "\t" + self.v_line + "\t\t" + self.v_line + "\t\t     "  + self.v_line +  "          " + self.v_line + " {} ".format("sudo nmap -sn --disable-arp-ping -6 fe80::1/64") + (" "*15)+ self.v_line,
            self.v_line + "\t" + self.l_end + (self.h_line*15) + self.b_end + (self.h_line*20) + self.b_end + (self.h_line*10) + self.cross + (self.h_line*63) + self.r_end,   
            self.v_line + "\t" + self.v_line + " LFI Attack    " + "\t\t\t\t" + self.v_line + " {}  ".format(self.inconclusive) + "\t\t\t\t\t\t" + self.v_line,
            self.v_line + "\t" + self.v_line + "\t\t\t\t\t\t" + self.v_line + " {} ".format("1.- sudo python3 -m http.server 80") + (" "*27)+ self.v_line,
            self.v_line + "\t" + self.v_line + "\t\t\t\t\t\t" + self.v_line + " {} ".format("2.- curl http://") + in_bound_ipv4 + " "*(45-len(in_bound_ipv4)) + self.v_line,
            self.v_line + "\t" + self.v_line + "\t\t\t\t\t\t" + self.v_line + " {} ".format("3.- curl http://" + in_bound_ipv4 + "/etc/passwd") + " "*(34-len(in_bound_ipv4)) + self.v_line,
            self.b_l_corner + (self.h_line*7) + self.b_end + (self.h_line*15) + self.h_line + (self.h_line*20) + self.h_line+ (self.h_line*10) + self.b_end + (self.h_line*63) + self.b_r_corner
        ]


    def print_tst_table(self):
        print('\n')
        for row in self.tst_table:
            print(row)
            
      
      
# PT TABLE
#------------------------------------------------------------------------------------  
class PT_table:
    """PT_Table CLASS:
    
        * Operation: generate the tst_table.
        * Method used by the following methods: table_configuration.
        * Use the following methods: -.
        * Use the following clases: -.
        * Libraries needed: -.
    """
    
    def __init__(self):
        
        self.reset_color = '\033[1;0m'
        self.test_pass = '\033[1;32m' + "PASS" + '\033[1;0m'
        self.test_fail = '\033[1;31m' + "FAIL" + '\033[1;0m'
        self.test_skip = '\033[1;35m' + "SKIP" + '\033[1;0m' 
        self.inconclusive = '\033[1;35m' + "INCONCLUSIVE:" + '\033[1;0m'
        self.h_line = chr(9472) 
        self.v_line = chr(9474)
        self.t_l_corner = chr(9484)
        self.t_r_corner = chr(9488) 
        self.b_l_corner = chr(9492)
        self.b_r_corner = chr(9496)
        self.l_end = chr(9500)
        self.r_end = chr(9508)
        self.t_end = chr(9516) 
        self.b_end = chr(9524)
        self.cross = chr(9532)
        
        self.tcp_broadcast = ''
        self.tcp_universal_broadcast = ''
        self.tct_multicast_ipv4 = ''
        self.tct_multicast_ipv6 = ''
        self.tcp_loopback_ipv4 = ''
        self.tcp_loopback_ipv6 = ''
        self.tcp_unspecified_ipv4 = ''
        self.tcp_unspecified_ipv6 = ''
        self.tcp_source_routing = ''
        self.tcp_strict_source_routing = ''
        self.tcp_record_route = ''
        self.tcp_timestamp = ''
        self.tcp_security = ''
        self.tcp_malformed_message = ''
        self.tcp_incomplete_message_1 = ''
        self.tcp_incomplete_message_2 = ''
        self.tcp_extended_security = ''
        self.tcp_commercial_security = ''
        self.tcp_link_local_source_ipv4 = ''
        self.tcp_link_local_source_ipv6 = ''
        self.tcp_link_local_destination_ipv4 = ''
        self.tcp_link_local_destination_ipv6 = ''
        
        self.pt_table = []
        
        
    def set_tcp_broadcast(self,check,run):
        if run:
            if check:
                self.tcp_broadcast = self.test_fail
            else:
                self.tcp_broadcast = self.test_pass
        else:
            self.tcp_broadcast = self.test_skip

    def set_tcp_universal_broadcast(self,check,run):
        if run:
            if check:
                self.tcp_universal_broadcast = self.test_fail
            else:
                self.tcp_universal_broadcast = self.test_pass
        else:
            self.tcp_universal_broadcast = self.test_skip
            
    def set_tcp_multicast_ipv4(self,check,run):
        if run:
            if check:
                self.tct_multicast_ipv4 = self.test_fail
            else:
                self.tct_multicast_ipv4 = self.test_pass
        else:
            self.tct_multicast_ipv4 = self.test_skip
            
    def set_tcp_multicast_ipv6(self,check,run):
        if run:
            if check:
                self.tct_multicast_ipv6 = self.test_fail
            else:
                self.tct_multicast_ipv6 = self.test_pass
        else:
            self.tct_multicast_ipv6 = self.test_skip
    
    def set_tcp_loopback_ipv4(self,check,run):
        if run:
            if check:
                self.tcp_loopback_ipv4 = self.test_fail
            else:
                self.tcp_loopback_ipv4 = self.test_pass
        else:
            self.tcp_loopback_ipv4 = self.test_skip
            
    def set_tcp_loopback_ipv6(self,check,run):
        if run:
            if check:
                self.tcp_loopback_ipv6 = self.test_fail
            else:
                self.tcp_loopback_ipv6 = self.test_pass
        else:
            self.tcp_loopback_ipv6 = self.test_skip

    def set_tcp_unspecified_ipv4(self,check,run):
        if run:
            if check:
                self.tcp_unspecified_ipv4 = self.test_fail
            else:
                self.tcp_unspecified_ipv4 = self.test_pass
        else:
            self.tcp_unspecified_ipv4 = self.test_skip
            
    def set_tcp_unspecified_ipv6(self,check,run):
        if run:
            if check:
                self.tcp_unspecified_ipv6 = self.test_fail
            else:
                self.tcp_unspecified_ipv6 = self.test_pass
        else:
            self.tcp_unspecified_ipv6 = self.test_skip
            
    def set_tcp_source_routing(self,check,run):
        if run:
            if check:
                self.tcp_source_routing = self.test_fail
            else:
                self.tcp_source_routing = self.test_pass
        else:
            self.tcp_source_routing = self.test_skip
    
    def set_tcp_strict_source_routing(self,check,run):
        if run:
            if check:
                self.tcp_strict_source_routing = self.test_fail
            else:
                self.tcp_strict_source_routing = self.test_pass
        else:
            self.tcp_strict_source_routing = self.test_skip

    def set_tcp_record_route(self,check,run):
        if run:
            if check:
                self.tcp_record_route = self.test_fail
            else:
                self.tcp_record_route = self.test_pass
        else:
            self.tcp_record_route = self.test_skip

    def set_tcp_timestamp(self,check,run):
        if run:
            if check:
                self.tcp_timestamp = self.test_fail
            else:
                self.tcp_timestamp = self.test_pass
        else:
            self.tcp_timestamp = self.test_skip
            
    def set_tcp_security (self,check,run):
        if run:
            if check:
                self.tcp_security  = self.test_fail
            else:
                self.tcp_security  = self.test_pass
        else:
            self.tcp_security = self.test_skip
            
    def set_tcp_malformed_message(self,check,run):
        if run:
            if check:
                self.tcp_malformed_message = self.test_fail
            else:
                self.tcp_malformed_message = self.test_pass
        else:
            self.tcp_malformed_message = self.test_skip
    
    def set_tcp_incomplete_message_1(self,check,run):
        if run:
            if check:
                self.tcp_incomplete_message_1 = self.test_fail
            else:
                self.tcp_incomplete_message_1 = self.test_pass
        else:
            self.tcp_incomplete_message_1 = self.test_skip

    def set_tcp_incomplete_message_2(self,check,run):
        if run:
            if check:
                self.tcp_incomplete_message_2 = self.test_fail
            else:
                self.tcp_incomplete_message_2 = self.test_pass
        else:
            self.tcp_incomplete_message_2 = self.test_skip

    def set_tcp_extended_security(self,check,run):
        if run:
            if check:
                self.tcp_extended_security = self.test_fail
            else:
                self.tcp_extended_security = self.test_pass
        else:
            self.tcp_extended_security = self.test_skip
            
    def set_tcp_commercial_security(self,check,run):
        if run:
            if check:
                self.tcp_commercial_security = self.test_fail
            else:
                self.tcp_commercial_security = self.test_pass
        else:
            self.tcp_commercial_security = self.test_skip
            
    def set_tcp_link_local_source_ipv4(self,check,run):
        if run:
            if check:
                self.tcp_link_local_source_ipv4 = self.test_fail
            else:
                self.tcp_link_local_source_ipv4 = self.test_pass
        else:
            self.tcp_link_local_source_ipv4 = self.test_skip
    
    def set_tcp_link_local_source_ipv6(self,check,run):
        if run:
            if check:
                self.tcp_link_local_source_ipv6 = self.test_fail
            else:
                self.tcp_link_local_source_ipv6 = self.test_pass
        else:
            self.tcp_link_local_source_ipv6 = self.test_skip
            
    def set_tcp_link_local_destination_ipv4(self,check,run):
        if run:
            if check:
                self.tcp_link_local_destination_ipv4 = self.test_fail
            else:
                self.tcp_link_local_destination_ipv4 = self.test_pass
        else:
            self.tcp_link_local_destination_ipv4 = self.test_skip
    
    def set_tcp_link_local_destination_ipv6(self,check,run):
        if run:
            if check:
                self.tcp_link_local_destination_ipv6 = self.test_fail
            else:
                self.tcp_link_local_destination_ipv6 = self.test_pass
        else:
            self.tcp_link_local_destination_ipv6 = self.test_skip
        
        
    def set_pt_table(self,sending_in_ipv4):
        
        end_1 = self.l_end  + (self.h_line*23) + self.cross + (self.h_line*20) + self.cross +  (self.h_line*10) + self.cross + (self.h_line*63)+ self.r_end
        end_2 = self.v_line + "\t\t\t" + self.l_end + (self.h_line*20) + self.cross +  (self.h_line*10) + self.cross + (self.h_line*63)+ self.r_end
        
        self.pt_table = [

            self.t_l_corner + (self.h_line*119) + self.t_r_corner,
            self.v_line + "\t\t\t\t\t\t\t" + "PT TABLE" + "\t\t\t\t\t\t\t" + self.v_line,      
            self.b_l_corner + (self.h_line*119) + self.b_r_corner,
            self.t_l_corner + (self.h_line*23) + self.t_end + (self.h_line*20) + self.t_end + (self.h_line*10) + self.t_end + (self.h_line*63) + self.t_r_corner,
            self.v_line + " Invalid source        " + self.v_line + " Broadcast          " + self.v_line +  "   IPv4   " + self.v_line + "\t\t\t\t" + "{}".format(self.tcp_broadcast) + "\t\t\t\t"+ self.v_line,
            end_2,
            self.v_line + "\t\t\t" + self.v_line + " Universal          " + self.v_line +  "   IPv4   " + self.v_line + "\t\t\t\t" + "{}".format(self.tcp_universal_broadcast) + "\t\t\t\t" + self.v_line,
            self.v_line + "\t\t\t" + self.v_line + " broadcast          " + self.v_line + "\t\t"  + self.v_line + "\t\t\t\t\t\t\t\t" + self.v_line,
            end_2,
            self.v_line + "\t\t\t" + self.v_line + " Multicast          " + self.v_line +  "   IPv4   " + self.v_line + "\t\t\t\t" + "{}".format(self.tct_multicast_ipv4) + "\t\t\t\t"+ self.v_line,
            self.v_line + "\t\t\t" + self.v_line + "\t\t     " + self.l_end +  (self.h_line*10)  + self.cross + (self.h_line*63) + self.r_end,
            self.v_line + "\t\t\t" + self.v_line + "\t\t     " + self.v_line +  "   IPv6   " + self.v_line + "\t\t\t\t" + "{}".format(self.tct_multicast_ipv6) + "\t\t\t\t"+ self.v_line,
            end_2,
            self.v_line + "\t\t\t" + self.v_line + " Loopback           " + self.v_line +  "   IPv4   " + self.v_line + "\t\t\t\t" + "{}".format(self.tcp_loopback_ipv4) + "\t\t\t\t"+ self.v_line,
            self.v_line + "\t\t\t" + self.v_line + "\t\t     " + self.l_end +  (self.h_line*10)  + self.cross + (self.h_line*63) + self.r_end,
            self.v_line + "\t\t\t" + self.v_line + "\t\t     " + self.v_line +  "   IPv6   " + self.v_line + "\t\t\t\t" + "{}".format(self.tcp_loopback_ipv6) + "\t\t\t\t"+ self.v_line,
            end_2,
            self.v_line + "\t\t\t" + self.v_line + " Unspecified        " + self.v_line +  "   IPv4   " + self.v_line + "\t\t\t\t" + "{}".format(self.tcp_unspecified_ipv4) + "\t\t\t\t"+ self.v_line,
            self.v_line + "\t\t\t" + self.v_line + "\t\t     " + self.l_end +  (self.h_line*10)  + self.cross + (self.h_line*63) + self.r_end,
            self.v_line + "\t\t\t" + self.v_line + "\t\t     " + self.v_line +  "   IPv6   " + self.v_line + "\t\t\t\t" + "{}".format(self.tcp_unspecified_ipv6) + "\t\t\t\t"+ self.v_line,
            end_1,
            
            self.v_line + " Insecure " + "\t\t" + self.v_line + " Source routing     " + self.v_line +  "   IPv4   " + self.v_line + "\t\t\t\t" + "{}".format(self.tcp_source_routing) + "\t\t\t\t"+ self.v_line,
            self.v_line + " IP options" + "\t        " + self.l_end + (self.h_line*20) + self.cross +  (self.h_line*10) + self.cross + (self.h_line*63)+ self.r_end,
            self.v_line + "\t\t\t" + self.v_line + " Strict source      " + self.v_line +  "   IPv4   " + self.v_line + "\t\t\t\t" + "{}".format(self.tcp_strict_source_routing) + "\t\t\t\t"+ self.v_line,
            self.v_line + "\t\t\t" + self.v_line + " routing            " + self.v_line + "\t\t"  + self.v_line + "\t\t\t\t\t\t\t\t" + self.v_line,
            end_2,
            self.v_line + "\t\t\t" + self.v_line + " Record route       " + self.v_line +  "   IPv4   " + self.v_line + "\t\t\t\t" + "{}".format(self.tcp_record_route) + "\t\t\t\t"+ self.v_line,
            end_2,
            self.v_line + "\t\t\t" + self.v_line + " Security           " + self.v_line +  "   IPv4   " + self.v_line + "\t\t\t\t" + "{}".format(self.tcp_security) + "\t\t\t\t"+ self.v_line,
            end_2,
            self.v_line + "\t\t\t" + self.v_line + " Extended security  " + self.v_line +  "   IPv4   " + self.v_line + "\t\t\t\t" + "{}".format(self.tcp_extended_security) + "\t\t\t\t"+ self.v_line,
            end_2,
            self.v_line + "\t\t\t" + self.v_line + " Commercial         " + self.v_line +  "   IPv4   " + self.v_line + "\t\t\t\t" + "{}".format(self.tcp_commercial_security) + "\t\t\t\t"+ self.v_line,
            end_2,
            self.v_line + "\t\t\t" + self.v_line + " Malformed          " + self.v_line +  "   IPv4   " + self.v_line + "\t\t\t\t" + "{}".format(self.tcp_malformed_message) + "\t\t\t\t"+ self.v_line,
            end_2,
            self.v_line + "\t\t\t" + self.v_line + " Incomplete_1       " + self.v_line +  "   IPv4   " + self.v_line + "\t\t\t\t" + "{}".format(self.tcp_incomplete_message_1) + "\t\t\t\t"+ self.v_line,
            end_2,
            self.v_line + "\t\t\t" + self.v_line + " Incomplete_2       " + self.v_line +  "   IPv4   " + self.v_line + "\t\t\t\t" + "{}".format(self.tcp_incomplete_message_2) + "\t\t\t\t"+ self.v_line,
            end_2,
            self.v_line + "\t\t\t" + self.v_line + " Source             " + self.v_line +  "   IPv4   " + self.v_line + "\t\t\t\t" + "{}".format(self.tcp_link_local_source_ipv4) + "\t\t\t\t"+ self.v_line,
            self.v_line + "\t\t\t" + self.v_line + " Link-Local         " + self.l_end +  (self.h_line*10)  + self.cross + (self.h_line*63) + self.r_end,
            self.v_line + "\t\t\t" + self.v_line + "\t\t     " + self.v_line +  "   IPv6   " + self.v_line + "\t\t\t\t" + "{}".format(self.tcp_link_local_source_ipv6) + "\t\t\t\t"+ self.v_line,
            end_2,
            self.v_line + "\t\t\t" + self.v_line + " Destination        " + self.v_line +  "   IPv4   " + self.v_line + "\t\t\t\t" + "{}".format(self.tcp_link_local_destination_ipv4) + "\t\t\t\t"+ self.v_line,
            self.v_line + "\t\t\t" + self.v_line + " Link-Local         " + self.l_end +  (self.h_line*10)  + self.cross + (self.h_line*63) + self.r_end,
            self.v_line + "\t\t\t" + self.v_line + "\t\t     " + self.v_line +  "   IPv6   " + self.v_line + "\t\t\t\t" + "{}".format(self.tcp_link_local_destination_ipv6) + "\t\t\t\t"+ self.v_line,
            self.l_end  + (self.h_line*23) + self.b_end + (self.h_line*20) + self.cross +  (self.h_line*10) + self.cross + (self.h_line*63)+ self.r_end,
            
            
            self.v_line + " Port scaning with CONNECT " + "\t\t     " + self.v_line +  "   IPv4   " + self.v_line + " {} ".format(self.inconclusive) + "\t\t\t\t\t\t" + self.v_line,
            self.v_line + "\t\t\t\t\t     " + self.v_line +  "\t\t" + self.v_line + " {}".format("sudo nmap -sT " + sending_in_ipv4 + " --reason") + " " * (39-len(sending_in_ipv4))+ self.v_line,
            self.b_l_corner + (self.h_line*44) + self.b_end +  (self.h_line*10)  + self.b_end + (self.h_line*63) + self.b_r_corner,
            ]
        
        
    def print_pt_table(self):
        print('\n')
        for row in self.pt_table:
            print(row)
      
 
                
# SET TABLE SETTINGS
#------------------------------------------------------------------------------------
def table_configuration(table,title,check,run):

    """table_configuration METHOD:
    
        * Operation: sets the PASS or FAIL key in the TST_table or PT_table for 
                    each message, as appropriate. 
        * Method used by the following methods: -.
        * Use the following methods: -.
        * Use the following clases: TST_table, PT_table.
        * Libraries needed: -.
        
        * Input arguments:
            -table: a TST_table object or a PT_table object. <Object type>.
            -title: the title of the message. <String type>.
            -check: the check of the message. <Bool list type>.
        
    """    

    if title == "IPv4_fragment_overlap":
        table.set_ipv4_fragment_overlap(check,run)
    elif title == "IPv6_fragment_overlap":
        table.set_ipv6_fragment_overlap(check,run)
    elif title == "TCP_Same_dst_and_src_IPv4":
        table.set_tcp_same_dst_and_src_ipv4(check,run)
    elif title == "TCP_Same_dst_and_src_IPv6":
        table.set_tcp_same_dst_and_src_ipv6(check,run)
    elif title == "ICMPv4_Ping_of_death":
        table.set_icmpv4_ping_of_death(check,run)
    elif title == "ICMPv6_Ping_of_death":
        table.set_icmpv6_ping_of_death(check,run)
    elif title == "TCP_NULL_IPv4":
        table.set_tcp_null_ipv4(check,run)
    elif title == "TCP_NULL_IPv6":
        table.set_tcp_null_ipv6(check,run)
    elif title == "TCP_SYN_FIN_IPv4":
        table.set_tcp_syn_fin_ipv4(check,run)
    elif title == "TCP_SYN_FIN_IPv6":
        table.set_tcp_syn_fin_ipv6(check,run)
    elif title == "TCP_FIN_IPv4":
        table.set_tcp_fin_ipv4(check,run)
    elif title == "TCP_FIN_IPv6":
        table.set_tcp_fin_ipv6(check,run)
    elif title == "TCP_SYN_RST_IPv4":
        table.set_tcp_syn_rst_ipv4(check,run)
    elif title == "TCP_SYN_RST_IPv6":
        table.set_tcp_syn_rst_ipv6(check,run)
    elif title == "UDP_Bomb_IPv4":
        table.set_udp_bomb_ipv4(check,run)
    elif title == "UDP_Bomb_IPv6":
        table.set_udp_bomb_ipv6(check,run)
    elif title == "UDP_DoS_Chargen_IPv4":
        table.set_udp_dos_chargen_ipv4(check,run)
    elif title == "UDP_DoS_Chargen_IPv6":
        table.set_udp_dos_chargen_ipv6(check,run)
    elif title == "ICMPv4_flood":
        table.set_icmpv4_flood(check,run)
    elif title == "ICMPv6_flood":
        table.set_icmpv6_flood(check,run)
    elif title == "TCP_flood_IPv4":
        table.set_tcp_flood_ipv4(check,run)
    elif title == "TCP_flood_IPv6":
        table.set_tcp_flood_ipv6(check,run)
        
    
    elif title == "TCP_Broadcast":
        table.set_tcp_broadcast(check,run)
    elif title == "TCP_Universal_Broadcast":
        table.set_tcp_universal_broadcast(check,run)
    elif title == "TCP_Multicast_IPv4":
        table.set_tcp_multicast_ipv4(check,run)
    elif title == "TCP_Multicast_IPv6":
        table.set_tcp_multicast_ipv6(check,run)
    elif title == "TCP_Loopback_IPv4":
        table.set_tcp_loopback_ipv4(check,run)
    elif title == "TCP_Loopback_IPv6":
        table.set_tcp_loopback_ipv6(check,run)
    elif title == "TCP_Unspecified_IPv4":
        table.set_tcp_unspecified_ipv4(check,run)
    elif title == "TCP_Unspecified_IPv6":
        table.set_tcp_unspecified_ipv6(check,run)
    elif title == "TCP_Source_Routing":
        table.set_tcp_source_routing(check,run)
    elif title == "TCP_Strict_Source_Routing":
        table.set_tcp_strict_source_routing(check,run)
    elif title == "TCP_Record_Route":
        table.set_tcp_record_route(check,run)
    elif title == "TCP_Timestamp":
        table.set_tcp_timestamp(check,run)
    elif title == "TCP_Security":
        table.set_tcp_security(check,run)
    elif title == "TCP_Malformed":
        table.set_tcp_malformed_message(check,run)
    elif title == "TCP_Incomplete_1":
        table.set_tcp_incomplete_message_1(check,run)
    elif title == "TCP_Incomplete_2":
        table.set_tcp_incomplete_message_2(check,run)
    elif title == "TCP_Extended_Security":
        table.set_tcp_extended_security(check,run)
    elif title == "TCP_Commercial_Security":
        table.set_tcp_commercial_security(check,run)
    elif title == "TCP_Link_Local_source_IPv4":
        table.set_tcp_link_local_source_ipv4(check,run)
    elif title == "TCP_Link_Local_source_IPv6":
        table.set_tcp_link_local_source_ipv6(check,run)
    elif title == "TCP_Link_Local_destination_IPv4":
        table.set_tcp_link_local_destination_ipv4(check,run)
    elif title == "TCP_Link_Local_destination_IPv6":
        table.set_tcp_link_local_destination_ipv6(check,run)
    
        
        
