#!/usr/bin/env python3

#            +++++++++++++++++++++++++++++++++++++++++++
#            +             SNBirdie main               +
#            +           ------------------            +
#            +             A testing tool              +
#            +                   by                    +
#            +        Victor M Molinos Santiago        +
#            +++++++++++++++++++++++++++++++++++++++++++


    
## AUXILIARY LIBRARIES
###------------------------------------------------------------------------------------------------------------------------------------
import os
import time
import sys
import shutil
import signal
import argparse
import textwrap
import netifaces
import subprocess
from ping3 import ping
from tabulate import tabulate

#import snblibrary as snblib
import snbirdie.snblibrary as snblib


def main():
    
    
    ## CLI
    ###------------------------------------------------------------------------------------------------------------------------------------
    parser = argparse.ArgumentParser(
        prog="SNBirdie",
        formatter_class=argparse.MetavarTypeHelpFormatter,
        usage=textwrap.dedent("""\
            
            
            
                                           _//_
                                          /.__.\\
                                          \ \/ /
                                       '__/    \ 
                                        \-      )
                                         \_____/
                                ___________| |_________
                                           " "
                                

            
                ███████╗███╗   ██╗██████╗ ██╗██████╗ ██████╗ ██╗███████╗
                ██╔════╝████╗  ██║██╔══██╗██║██╔══██╗██╔══██╗██║██╔════╝
                ███████╗██╔██╗ ██║██████╔╝██║██████╔╝██║  ██║██║█████╗  
                ╚════██║██║╚██╗██║██╔══██╗██║██╔══██╗██║  ██║██║██╔══╝  
                ███████║██║ ╚████║██████╔╝██║██║  ██║██████╔╝██║███████╗
                ╚══════╝╚═╝  ╚═══╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚══════╝
                
            Snitching birdie is an IPS tester that allows you to send a set of testing messages 
            from an OUT_BOUND machine and detect their arrival at an IN_BOUND machine.
            
            {*} DEFAULT MODE: It only sends the full set of messages but don't detect their arrival.
            
            {*} DETECTION MODE: It sends the full set of messages and detect their arrival.
            
            {*} SELECTIVE SENDER: It sends a selective set of messages
            
            DEFAULT {}: [-f, -tst, -pt, -V, -os, -ip, -m4, -m6, -l4, -l6]
                      
            DETECTION {-D}: [-d, -f, -tst, -pt, -V, -oc, -ic, -os, -ip, -m4, -m6, -l4, -l6]
                        
            SELECTIVE SENDER {-S}: [-d, -f, -oc, -ic, -os, -ip, -m4, -m6, -l4, -l6]
                        
            Examples:
            ---------
                snbirdie -os eth1 -ip 192.168.1.200 -f 50
                snbirdie -D -d 4 -oc eth2 -ic eth0 -os eth1 -ip 192.168.1.200 
                snbirdie -S -oc eth2 -ic eth0 -os eth1 -ip 192.168.1.200  
                
                """)
            )
    
    parser.add_argument('-v','--version', action='version', version='%(prog)s 1.0')
    
    #----------------------------------------------------------------- OPTIONS ----------------------------------------------------------------------------
    parser.add_argument('-d', type=int, default=3, help=("Delay in seconds before inspecting the catch. (Default: 3s)"))
    parser.add_argument('-f', type=int, default=50, help=("Number of messages for flooding. (Default: 50)")) 
    parser.add_argument('-tst', action='store_true', default=False, help=("Only TST messages."))
    parser.add_argument('-pt', action='store_true', default=False, help=("Only PT messages."))
    parser.add_argument('-V', action='store_true', default=False, help=("Enable verbose option."))
    
    #------------------------------------------------------------ OPERATING MODES -------------------------------------------------------------------------
    parser.add_argument('-D', '--detection', action='store_const', default=0, const=1, help=("Enable detection mode.")) 
    parser.add_argument('-S', '--s_sender', action='store_const', default=0, const=1, help=("Enable selective sender mode.")) 
    
    #---------------------------------------------------------- REQUIRED PARAMETERS -----------------------------------------------------------------------
    parser.add_argument('-oc','--out_control_iface', type=str, required=True, help=("Ethernet interface for the ssh connection on the OUT_BOUND machine. REQUIRED"))
    parser.add_argument('-ic','--in_control_iface', type=str, required=True, help=("Ethernet interface for the ssh connection on the IN_BOUND machine. REQUIRED")) 
    parser.add_argument('-os','--out_sending_iface', type=str, required=True, help=("Ethernet sending interface on OUT_BOUND machine. REQUIRED"))
    parser.add_argument('-ip','--in_listening_ip', type=str, required=True, help=("IN_BOUND sending IPv4. REQUIRED."))
     
    #---------------------------------------------------------- OPTIONAL PARAMETERS -----------------------------------------------------------------------
    parser.add_argument('-m4','--multicast_ip4', type=str, default='244.0.0.1', help=("Multicast sending IPv4. (Default: 244.0.0.1)"))
    parser.add_argument('-m6','--multicast_ip6', type=str, default='ff02::1', help=("Multicast sending IPv6. (Default: ff02::1)")) 
    parser.add_argument('-l4','--link_local_ip4', type=str, default='169.254.0.1', help=("Local sending IPv4. (Default: 169.254.0.1)"))
    parser.add_argument('-l6','--link_local_ip6', type=str, default='fe80::1', help=("Local sending IPv6. (Default: fe80::1)"))

    args = parser.parse_args()



    # MAIN PARAMETERS
    delay = args.d
    flood = args.f
    verbose = args.V
    tst_only = args.tst
    pt_only = args.pt
    
    aux_mode = str(args.detection) + str(args.s_sender)
        
        
    ssh_out_iface = args.out_control_iface
    ssh_in_iface = args.in_control_iface
    sending_out_iface = args.out_sending_iface
    listening_in_ip4 = args.in_listening_ip
    
    multicastip4 = args.multicast_ip4
    multicastip6 = args.multicast_ip6
    localip4 = args.link_local_ip4
    localip6 = args.link_local_ip6
    pcaps_path = "./snb_pcaps"
    birdie = b'\xf0\x9F\x90\xA6'.decode("utf-8")
           
    # Colors
    red = '\033[1;31m'
    purple = '\033[1;35m'
    green = '\033[1;32m'
    reset_color = '\033[1;0m'
    blue = '\033[34m'
    white = '\033[1;37m'
    under_white = '\033[1;4;37m'
    reset_undercolor = '\033[1;4;0m'
    
    
    # Title mode
    os.system("clear")
    print('\n')
    if aux_mode == '00':
        mode = "Default"
    elif aux_mode == '01':
        mode = "Selective Sender"
    elif aux_mode == '10':
        mode = "Detection"
    else:
        print(red + "Error: " + reset_color + "You must select only one mode between Default {}, Selective Sender {-S} and Detection {-D}")
        exit()
    
    print(birdie + red + " " + mode + " Mode " + reset_color + birdie)
    
    ## NET INFORMATION
    # OUT_BOUND machine
    interfaces = netifaces.interfaces() # All interfaces in this machine (OUT_BOUND)
    for interface in interfaces:
        if interface == 'lo':
            loopbackip4 = netifaces.ifaddresses(interface)[2][0]['addr'] # Loopback OUT_BOUND ipv4
            loopbackip6 = netifaces.ifaddresses(interface)[10][0]['addr'] # Loopback OUT_BOUND ipv6
            
        if mode == 'Detection' or mode == 'Selective Sender': 
            if interface == ssh_out_iface: # Loocking for ssh OUT_BOUND interface
                ssh_out_ip4 = netifaces.ifaddresses(interface)[2][0]['addr'] # ssh OUT_BOUND ipv4
            
        if interface == sending_out_iface: # Loocking for sending OUT_BOUND interface
            sending_out_ip4 = netifaces.ifaddresses(interface)[2][0]['addr'] # Sending OUT_BOUND ipv4
            broadcastip = netifaces.ifaddresses(interface)[2][0]['broadcast'] # Broadcast OUT_BOUND ipv4
            sending_out_ip6 = netifaces.ifaddresses(interface)[10][0]['addr'].split("%")[0] # Sending OUT_BOUND ipv6. For example 'fe80::20c:29ff:fe5a:5a88%eth0'
    
    # IN_BOUND machine
    listening_in_iface = snblib.net_info(listening_in_ip4,'_')
    _, listening_in_ip6 = snblib.net_info(listening_in_ip4,listening_in_iface)
    if mode == 'Detection' or mode == 'Selective Sender':
        ssh_in_ip4,_ = snblib.net_info(listening_in_ip4,ssh_in_iface)
        
    
    
    # Main info
    main_info = {"OUT_BOUND":["Sending interface: {}".format(sending_out_iface),"Sending IPv4: {}".format(sending_out_ip4),"Sending IPv6: {}".format(sending_out_ip6), 
                                "Control interface: {}".format(ssh_out_iface),"Control IPv4: {}".format(ssh_out_ip4), "Broadcast IPv4: {}".format(broadcastip),
                                "Loopback IPv4: {}".format(loopbackip4),"Loopback IPv6: {}".format(loopbackip6)],
                "IN_BOUND":["Listening interface: {}".format(listening_in_iface),"Listening IPv4: {}".format(listening_in_ip4),"Listening IPv6: {}".format(listening_in_ip6), 
                                "Control interface: {}".format(ssh_in_iface),"Control IPv4: {}".format(ssh_in_ip4)]}
    print('\t\t\t\t\t' + under_white + "Main Info" + reset_color)
    print(tabulate(main_info,headers='keys',tablefmt='fancy_grid',colalign=('left','left')))
    print('\n')
    


    ## SELECTIVE SENDER MODE
    ###------------------------------------------------------------------------------------------------------------------------------------
    if mode == 'Selective Sender':
        
        # Generating the snb_pcaps folder
        try: # Try to generate snb_pcaps folder.
            os.mkdir("./snb_pcaps") 
        except FileExistsError: # If it exist, overwrite folder.
            shutil.rmtree("./snb_pcaps")
            os.mkdir("./snb_pcaps") 

        try: # Showing the menu
            tst_titles,pt_titles = snblib.message_configurator(False,False,False,True,_,_,_,_,_,_,_,_,_,_,_,_,_,_)
            
            tst_index = list(range(1,len(tst_titles)+1))    
            pt_index = list(range(len(tst_index)+2,len(tst_index)+2+len(pt_titles)))
            
            titles_dic = {"tst index":tst_index,"tst_messages":tst_titles,"pt index":pt_index,"pt_messages":pt_titles}
            print("\t\t\t\t\t" + under_white + "Message Table" + reset_undercolor)
            print(tabulate(titles_dic,headers='keys',tablefmt='fancy_grid',numalign='left'))
            
            print('\n')
            indexes = input("Choose the indexes of the messages to be sent: ")
            indexes = indexes.split(" ")
            
            indexes = [int(x) for x in indexes]
            
            maxim = max(indexes)
            minim = min(indexes)
            while pt_index[-1]<maxim or minim<=0:
                indexes = input("You must choose indexes between 1 and " + str(pt_index[-1]) + ": ")
                indexes = indexes.split(" ")
                
                indexes = [int(x) for x in indexes]
                
                maxim = max(indexes)
                minim = min(indexes)
             
        # Keyboard Interrupt (EXIT the programme). 
        except KeyboardInterrupt:
            print("\n\n\t\t\t" + red + "Keyboard Interrupt!" + reset_color + "\n\t\t\t\t" + "EXIT!" + '\n')
            exit() 
             
        # Getting the messages list
        messages = snblib.message_configurator(False,False,indexes,False,sending_out_iface,sending_out_ip4,sending_out_ip6,listening_in_ip4,listening_in_ip6,
                                        broadcastip,multicastip4,multicastip6,localip4,localip6,loopbackip4,loopbackip6,flood,verbose)     

        print('\n')

        # Sending messages     
        for message in messages: 
            try:
                
                # Connection check
                skip = False
                while not(skip):
                    run = False
                    aux_conn = ping(listening_in_ip4,timeout=2)
                    
                    if bool(aux_conn):
                        skip = True
                        run = True
                    else:
                        for intent in range(2):
                            print('\n' + red + "ERROR: " + reset_color + "No connection to host {}".format(listening_in_ip4))
                            print("Attempting new connection...")
                            time.sleep(2)
                            aux_conn = ping(listening_in_ip4,timeout=2)
                            if bool(aux_conn):
                                skip = True
                                run = True
                                break
                            
                        if not(run):
                            print('\n' + red + "ERROR: " + reset_color + "No connection to host {}".format(listening_in_ip4))
                            print('The "' + message.title + '" message could not be sent!')
                            inp = input("Do you want to skip this test? (y/n): ")
                            while inp != 'y' and inp != 'n':
                                print('\n' + 'You must enter "y" or "n":')
                                inp = input("Do you want to skip this test? (y/n): ")
                                
                            if inp == 'y':
                                if verbose:
                                    print('\n' + "Skipping: " + purple + message.title + " message" + reset_color)
                                    
                                print('\n')
                                skip = True
                                run = False 
                         
                          
                # Main run
                if run:
                        
                    # Inconclusive messages
                    if message.inconclusive:
                        print(purple +  message.title + " message" + reset_color + ": " + red + "INCONCLUSIVE" + reset_color + '\n\n')
                            
                    # Ordinary Messages
                    else:
                        path = os.path.join(pcaps_path,message.title) # pcap path.
                        
                        # SSH connection.
                        connect = "ssh root@" + ssh_in_ip4 + " -b " + ssh_out_ip4 + " tcpdump -i " + listening_in_iface + " -U -v not port 22 -w - > " + path + ".pcap" 
                        p=subprocess.Popen(connect,shell=True,universal_newlines=True,stderr=subprocess.PIPE)     
                            
                        # Sender
                        p_stderr = p.stderr.readline() # stderr
                        if "listening on" in p_stderr or "data link type LINUX_SLL2" in p_stderr: # eth0/eth1 or any. If the connection was successfull...
                            
                            
                            # Send message
                            message.sender(message.title,message.ports,message.data)
                            
                            
                            # Delay 
                            start = time.time()
                            actual = time.time()-start
                            
                            while actual<delay: # Wait delay seconds.
                                actual = time.time()-start    
                                
                            
                            # Kill process 
                            try: # Kill all children subprocess.
                                snblib.kill_sons(os.getpgid(p.pid))
                            except:# If there is a trouble, kill SSH connection subprocess. 
                                subprocess.Popen.kill(p)
                                    
                            
                            # Check 
                            if verbose:
                                print(blue + "BPF FILTER: " + reset_color,message.filt)
                            check = message.check(path + ".pcap",message.filt,message.data,verbose)
                            if True in check:
                                if verbose:
                                    print(red + "FAIL" + reset_color + '\n\n')
                                                                        
                            else:
                                if verbose:
                                    print(green + "PASS" + reset_color + '\n\n')
                            
                            
                        # ssh connection errors    
                        elif "Connection refused" in p_stderr:
                            if verbose:
                                print(red + "ERROR: " + reset_color + "ssh connection refused!" + '\n')
                                snblib.kill_sons(os.getpgid(p.pid))
                                exit()
                        
                        else:
                            if verbose:
                                print(red + "ERROR: " + reset_color + "ssh connection error!: " + p_stderr + '\n')
                                snblib.kill_sons(os.getpgid(p.pid))
                                exit()                    
                    
            # Keyboard Interrupt (EXIT the programme). 
            except KeyboardInterrupt:
                print("\n\n\t\t\t" + red + "Keyboard Interrupt!" + reset_color + "\n\t\t\t\t" + "EXIT!" + '\n')
                snblib.show_cursor() 
                if p:
                    os.killpg(os.getpgid(p.pid), signal.SIGTERM)
    
    
        # Connection check
        print('\n' + purple + "Checking the connection status" + reset_color)
        aux_conn = ping(listening_in_ip4,timeout=2)
        
        if bool(aux_conn):
            print("The connection to host: " + listening_in_ip4 + " is " + green + "UP" + reset_color)
        else:
            print("The connection to host: " + listening_in_ip4 + " is " + red + "DOWN" + reset_color)

  
    
    ## DETECTION MODE
    ###------------------------------------------------------------------------------------------------------------------------------------
    elif mode == 'Detection':
        
        # Generating the snb_pcaps folder
        try: # Try to generate snb_pcaps folder.
            os.mkdir("./snb_pcaps") 
        except FileExistsError: # If it exist, overwrite folder.
            shutil.rmtree("./snb_pcaps")
            os.mkdir("./snb_pcaps") 

        # Preparing tables
        tst_table = snblib.TST_table()
        pt_table = snblib.PT_table()
        
        # Hide cursor and working phrase
        if not(verbose): 
            snblib.hide_cursor()
            sys.stdout.write(white + "Working" + reset_color)
            sys.stdout.flush()
            
        # Generating the full messages list  
        if tst_only and pt_only:
            print(red + "ERROR: " + reset_color + " You must select only the -tst flag or the -pt flag") 
            exit() 
        elif tst_only:
            messages = snblib.message_configurator(True,False,False,False,sending_out_iface,sending_out_ip4,sending_out_ip6,listening_in_ip4,listening_in_ip6,
                                                    broadcastip,multicastip4,multicastip6,localip4,localip6,loopbackip4,loopbackip6,flood,verbose)
        elif pt_only:
            messages = snblib.message_configurator(False,True,False,False,sending_out_iface,sending_out_ip4,sending_out_ip6,listening_in_ip4,listening_in_ip6,
                                                    broadcastip,multicastip4,multicastip6,localip4,localip6,loopbackip4,loopbackip6,flood,verbose)
        else:
            messages = snblib.message_configurator(True,True,False,False,sending_out_iface,sending_out_ip4,sending_out_ip6,listening_in_ip4,listening_in_ip6,
                                                    broadcastip,multicastip4,multicastip6,localip4,localip6,loopbackip4,loopbackip6,flood,verbose)
            
             
        # Sending messages     
        for message in messages: 
            try:
                
                # Connection check
                skip = False
                while not(skip):
                    run = False
                    aux_conn = ping(listening_in_ip4,timeout=2)
                    
                    if bool(aux_conn):
                        skip = True
                        run = True
                    else:
                        for intent in range(2):
                            print('\n' + red + "ERROR: " + reset_color + "No connection to host {}".format(listening_in_ip4))
                            print("Attempting new connection...")
                            time.sleep(2)
                            aux_conn = ping(listening_in_ip4,timeout=2)
                            if bool(aux_conn):
                                skip = True
                                run = True
                                break
                            
                        if not(run):
                            print('\n' + red + "ERROR: " + reset_color + "No connection to host {}".format(listening_in_ip4))
                            print('The "' + message.title + '" message could not be sent!')
                            inp = input("Do you want to skip this test? (y/n): ")
                            while inp != 'y' and inp != 'n':
                                print('\n' + 'You must enter "y" or "n":')
                                inp = input("Do you want to skip this test? (y/n): ")
                                
                            if inp == 'y':
                                if verbose:
                                    print('\n' + "Skipping: " + purple + message.title + " message" + reset_color)
                                    
                                print('\n')
                                skip = True
                                run = False 
                         
                          
                # Main run
                if run:
              
                    # Starting phrase
                    if verbose:
                        if message.title == "IPv4_fragment_overlap":
                            print(under_white + "--------------------------------------------- TST MESSAGES ---------------------------------------------" 
                                + reset_undercolor + '\n')
                        elif message.title == "TCP_Broadcast":
                            print('\n' + under_white + "--------------------------------------------- PT MESSAGES ---------------------------------------------" 
                                + reset_undercolor + '\n')
                        
                    # Inconclusive messages
                    if message.inconclusive:
                        if verbose:
                            print(purple +  message.title + " message" + reset_color + ": " + red + "INCONCLUSIVE" + reset_color + '\n\n')
                        
                        else: # Working...
                            sys.stdout.write('\r')
                            sys.stdout.flush()
                            sys.stdout.write("                  ")
                            sys.stdout.write('\r')
                            sys.stdout.flush()
                            sys.stdout.write(white + "Working." + reset_color)
                            sys.stdout.flush()
                            sys.stdout.write('\r')
                            sys.stdout.flush()
                            sys.stdout.write("                  ")
                            sys.stdout.write('\r')
                            sys.stdout.flush()
                            sys.stdout.write(white + "Working.." + reset_color)
                            sys.stdout.flush()
                            sys.stdout.write('\r')
                            sys.stdout.flush()
                            sys.stdout.write("                  ")
                            sys.stdout.write('\r')
                            sys.stdout.flush()
                            sys.stdout.write(white + "Working..." + reset_color)
                            sys.stdout.flush()
                            
                    # Ordinary Messages
                    else:
                        path = os.path.join(pcaps_path,message.title) # pcap path.
                        
                        
                        # SSH connection.
                        connect = "ssh root@" + ssh_in_ip4 + " -b " + ssh_out_ip4 + " tcpdump -i " + listening_in_iface + " -U -v not port 22 -w - > " + path + ".pcap" 
                        p=subprocess.Popen(connect,shell=True,universal_newlines=True,stderr=subprocess.PIPE)
                        
                        
                        # Working phrase
                        if not(verbose): 
                            sys.stdout.write('\r')
                            sys.stdout.flush()
                            sys.stdout.write("                  ")
                            sys.stdout.write('\r')
                            sys.stdout.flush()
                            sys.stdout.write(white + "Working." + reset_color)
                            sys.stdout.flush()
                            
                            
                        # Sender
                        p_stderr = p.stderr.readline() # stderr
                        if "listening on" in p_stderr or "data link type LINUX_SLL2" in p_stderr: # eth0/eth1 or any. If the connection was successfull...
                            
                            
                            # Send message
                            message.sender(message.title,message.ports,message.data)
                            
                            
                            # Working phrase
                            if not(verbose): 
                                sys.stdout.write('\r')
                                sys.stdout.flush()
                                sys.stdout.write("                  ") 
                                sys.stdout.write('\r')
                                sys.stdout.flush()
                                sys.stdout.write(white + "Working.." + reset_color)
                                sys.stdout.flush()
                            
                            
                            # Delay 
                            start = time.time()
                            actual = time.time()-start
                            
                            while actual<delay: # Wait delay seconds.
                                actual = time.time()-start    
                                
                            
                            # Kill process 
                            try: # Kill all children subprocess.
                                snblib.kill_sons(os.getpgid(p.pid))
                            except:# If there is a trouble, kill SSH connection subprocess. 
                                subprocess.Popen.kill(p)
                                    
                            
                            # Check 
                            if verbose:
                                print(blue + "BPF FILTER: " + reset_color,message.filt)
                            check = message.check(path + ".pcap",message.filt,message.data,verbose)
                            if True in check:
                                if verbose:
                                    print(red + "FAIL" + reset_color + '\n\n')
                                                                        
                            else:
                                if verbose:
                                    print(green + "PASS" + reset_color + '\n\n')
                            
                            
                            # Store in a table list              
                            if message.mode_flag == 'TST':
                                snblib.table_configuration(tst_table,message.title,check,run)
                            elif message.mode_flag == 'PT':
                                snblib.table_configuration(pt_table,message.title,check,run)
                        
                        
                            # Working phrase
                            if not(verbose):
                                sys.stdout.write('\r')
                                sys.stdout.flush()
                                sys.stdout.write("                  ")
                                sys.stdout.write('\r')
                                sys.stdout.flush()
                                sys.stdout.write(white + "Working..." + reset_color)
                                sys.stdout.flush()
        
                                time.sleep(.5)
                            
                            
                        # ssh connection errors    
                        elif "Connection refused" in p_stderr:
                            if verbose:
                                print(red + "ERROR: " + reset_color + "ssh connection refused!" + '\n')
                                snblib.kill_sons(os.getpgid(p.pid))
                                exit()
                        
                        else:
                            if verbose:
                                print(red + "ERROR: " + reset_color + "ssh connection error!: " + p_stderr + '\n')
                                snblib.kill_sons(os.getpgid(p.pid))
                                exit()
                                
                else: # If not runs set SKIP in the corresponding table
                    if message.mode_flag == 'TST':
                            snblib.table_configuration(tst_table,message.title,check,run)
                    elif message.mode_flag == 'PT':
                        snblib.table_configuration(pt_table,message.title,check,run)                     

                    
            # Keyboard Interrupt (EXIT the programme). 
            except KeyboardInterrupt:
                print("\n\n\t\t\t" + red + "Keyboard Interrupt!" + reset_color + "\n\t\t\t\t" + "EXIT!" + '\n')
                snblib.show_cursor() 
                if p:
                    os.killpg(os.getpgid(p.pid), signal.SIGTERM)
    
    
        # Setting and printing tables
        if tst_only:
            tst_table.set_tst_table(listening_in_ip4,listening_in_ip6)
            tst_table.print_tst_table()
        elif pt_only:
            pt_table.set_pt_table(listening_in_ip4)
            pt_table.print_pt_table()
        else:
            tst_table.set_tst_table(listening_in_ip4,listening_in_ip6)
            tst_table.print_tst_table()

            pt_table.set_pt_table(listening_in_ip4)
            pt_table.print_pt_table()
                
                
                
    ## DEFAULT MODE
    ###------------------------------------------------------------------------------------------------------------------------------------             
    elif mode == 'Default':
        
        # Hide cursor and working phrase
        if not(verbose): 
            snblib.hide_cursor()
            sys.stdout.write(white + "Working" + reset_color)
            sys.stdout.flush()
            
        # Generating the messages list  
        if tst_only and pt_only:
            print(red + "ERROR: " + reset_color + " You must select only the -tst flag or the -pt flag") 
            exit() 
        elif tst_only:
            messages = snblib.message_configurator(True,False,False,False,sending_out_iface,sending_out_ip4,sending_out_ip6,listening_in_ip4,listening_in_ip6,
                                                    broadcastip,multicastip4,multicastip6,localip4,localip6,loopbackip4,loopbackip6,flood,verbose)
        elif pt_only:
            messages = snblib.message_configurator(False,True,False,False,sending_out_iface,sending_out_ip4,sending_out_ip6,listening_in_ip4,listening_in_ip6,
                                                    broadcastip,multicastip4,multicastip6,localip4,localip6,loopbackip4,loopbackip6,flood,verbose)
        else:
            messages = snblib.message_configurator(True,True,False,False,sending_out_iface,sending_out_ip4,sending_out_ip6,listening_in_ip4,listening_in_ip6,
                                                    broadcastip,multicastip4,multicastip6,localip4,localip6,loopbackip4,loopbackip6,flood,verbose)
            
             
        # Sending messages     
        for message in messages: 
            try:
                
                # Connection check
                skip = False
                while not(skip):
                    run = False
                    aux_conn = ping(listening_in_ip4,timeout=2)
                    
                    if bool(aux_conn):
                        skip = True
                        run = True
                    else:
                        for intent in range(2):
                            print('\n' + red + "ERROR: " + reset_color + "No connection to host {}".format(listening_in_ip4))
                            print("Attempting new connection...")
                            time.sleep(2)
                            aux_conn = ping(listening_in_ip4,timeout=2)
                            if bool(aux_conn):
                                skip = True
                                run = True
                                break
                            
                        if not(run):
                            print('\n' + red + "ERROR: " + reset_color + "No connection to host {}".format(listening_in_ip4))
                            print('The "' + message.title + '" message could not be sent!')
                            inp = input("Do you want to skip this test? (y/n): ")
                            while inp != 'y' and inp != 'n':
                                print('\n' + 'You must enter "y" or "n":')
                                inp = input("Do you want to skip this test? (y/n): ")
                                
                            if inp == 'y':
                                if verbose:
                                    print('\n' + "Skipping: " + purple + message.title + " message" + reset_color)
                                    
                                print('\n')
                                skip = True
                                run = False 
                         
                          
                # Main run
                if run:
                    
                    # Starting phrase
                    if verbose:
                        if message.title == "IPv4_fragment_overlap":
                            print(under_white + "--------------------------------------------- TST MESSAGES ---------------------------------------------" 
                                + reset_undercolor + '\n')
                        elif message.title == "TCP_Broadcast":
                            print('\n' + under_white + "--------------------------------------------- PT MESSAGES ---------------------------------------------" 
                                + reset_undercolor + '\n')
                        
                    # Inconclusive messages
                    if message.inconclusive:
                        if verbose:
                            print(purple +  message.title + " message" + reset_color + ": " + red + "INCONCLUSIVE" + reset_color + '\n\n')
                        
                        else: # Working...
                            sys.stdout.write('\r')
                            sys.stdout.flush()
                            sys.stdout.write("                  ")
                            sys.stdout.write('\r')
                            sys.stdout.flush()
                            sys.stdout.write(white + "Working." + reset_color)
                            sys.stdout.flush()
                            sys.stdout.write('\r')
                            sys.stdout.flush()
                            sys.stdout.write("                  ")
                            sys.stdout.write('\r')
                            sys.stdout.flush()
                            sys.stdout.write(white + "Working.." + reset_color)
                            sys.stdout.flush()
                            sys.stdout.write('\r')
                            sys.stdout.flush()
                            sys.stdout.write("                  ")
                            sys.stdout.write('\r')
                            sys.stdout.flush()
                            sys.stdout.write(white + "Working..." + reset_color)
                            sys.stdout.flush()
                            
                    # Ordinary Messages
                    else:
                        path = os.path.join(pcaps_path,message.title) # pcap path.
                        
                        
                        # Working phrase
                        if not(verbose): 
                            sys.stdout.write('\r')
                            sys.stdout.flush()
                            sys.stdout.write("                  ")
                            sys.stdout.write('\r')
                            sys.stdout.flush()
                            sys.stdout.write(white + "Working." + reset_color)
                            sys.stdout.flush()
                            
                            
                        # Send message
                        message.sender(message.title,message.ports,message.data)
                        
                        
                        # Working phrase
                        if not(verbose): 
                            sys.stdout.write('\r')
                            sys.stdout.flush()
                            sys.stdout.write("                  ") 
                            sys.stdout.write('\r')
                            sys.stdout.flush()
                            sys.stdout.write(white + "Working.." + reset_color)
                            sys.stdout.flush()
                            sys.stdout.write('\r')
                            sys.stdout.flush()
                            sys.stdout.write("                  ")
                            sys.stdout.write('\r')
                            sys.stdout.flush()
                            sys.stdout.write(white + "Working..." + reset_color)
                            sys.stdout.flush()
    
                            time.sleep(.5)
                    
                    
            # Keyboard Interrupt (EXIT the programme). 
            except KeyboardInterrupt:
                print("\n\n\t\t\t" + red + "Keyboard Interrupt!" + reset_color + "\n\t\t\t\t" + "EXIT!" + '\n')
                snblib.show_cursor() 
                if p:
                    os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        
        
    # Show cursor and end  
    snblib.show_cursor()        
    print("\n\n\t\t\t\t\t" + white + "END!" + reset_color)

    
if __name__ == "__main__":
    main()
