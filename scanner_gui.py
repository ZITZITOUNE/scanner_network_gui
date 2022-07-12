import tkinter as tk
from tkinter import filedialog, END
from tkinter import messagebox
import socket
import nmap
import ipaddress
import ifaddr  # small library for finding network card IP settings
import psutil  # the psutil library is a big provider of system functions
import re  # re is a specialized library for regular expressions (regex)
from subprocess import (
    Popen,
    PIPE,
)  # Popen and PIPE are elements for managing subprocesses

regex_IP = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"

scanner = nmap.PortScanner()

class Window(tk.Tk):

    def __init__(self):
        
        #Widget initialization function
        
        tk.Tk.__init__(self)
        # Main Title
        self.label = tk.Label(self, text="ENTER IP (or help) : ")

        # Input User
        self.entry = tk.Entry(self)

        # Text Area
        self.text_result = tk.Text(self, height=20, width=70, bg="white")

        # Delete Button
        self.del_btn = tk.Button(self, text="CLEAR", fg="white", bg="red", command=lambda: self.text_result.delete(1.0,END))

        # Quit BTN
        self.quit_btn = tk.Button(self, text="QUIT", fg="white", bg="black", command=self.quit)

        # Ip Resolver BTN
        self.ip_scanner = tk.Button(self, text="RUN IP SCANNER", fg="white", bg="blue",command=self.ip_scanner)

        # Ip Resolver BTN
        self.port_scanner = tk.Button(self, text="RUN PORT SCANNER", fg="white", bg="blue",command=self.port_scanner)

        # Save As BTN
        self.save_as = tk.Button(self, text="SAVE AS",fg="white", bg="green", command=self.save_as)

        # Widgets Packing
        self.pack_widgets()

    def pack_widgets(self):
        self.label.pack()
        self.entry.pack()
        self.ip_scanner.pack(side="top", fill='x', expand='YES')
        self.port_scanner.pack(side="top", fill='x', expand='YES')
        self.text_result.pack()
        self.save_as.pack(side="bottom", fill='x', expand='YES')
        self.quit_btn.pack(side="bottom", fill='x', expand='YES')
        self.del_btn.pack(side="bottom", fill='x', expand='YES')

    def save_as(self):
        file = filedialog.asksaveasfile(mode='w', defaultextension=".txt")
        text_to_save = self.text_result.get(1.0, END)
        file.write(text_to_save)
        file.close()

    def port_scanner(self):
        hostname = self.entry.get()
        try:
            if hostname == "help" or hostname == "?":
                self.text_result.insert("1.0", "[-] ? or help , displays this help! \n")
                self.text_result.insert("2.0", "[-] xxx.xxx.xxx.xxx\n")
                self.text_result.insert("3.0", "[-] Launch nmap with the IP and give the open ports! \n") 
            elif ipaddress.ip_address(hostname):
                ipv4 = socket.gethostbyname(hostname)
                self.text_result.insert("1.0", "[-] IP : " + ipv4 + "\n")
                self.text_result.insert("2.0", "[-] nmap " + ipv4 + "\n")                
                scanner.scan(ipv4, arguments='-F')
                for port in scanner[ipv4]['tcp']:
                    port_data = scanner[ipv4]['tcp'][port]
                    self.text_result.insert("3.0", 'Port {0} Service : {1} \n'.format(port, port_data.get('name')))
        except socket.gaierror:
            tk.messagebox.showerror(title="ERROR ! ", message="ERROR ! ")


    def ip_scanner(self):
        req = ""
        req = self.entry.get()

        def StringIPv4ToIPv4(s):
            return 256 * (
                int(StringField(s, ".", 3))
                + 256 * (int(StringField(s, ".", 2)) + 256 * int(StringField(s, ".", 1)))
            )


        def IPv4ToStringIPv4(ip):
            a = int(ip % 256)
            ip = ip / 256
            b = int(ip % 256)
            ip = ip / 256
            c = int(ip % 256)
            ip = ip / 256
            d = int(ip % 256)
            return str(d) + "." + str(c) + "." + str(b) + "." + str(a)


        def MaskedIPv4(ip, mask):
            return ip & mask


        def StringField(s, sep, i):
            t = s.split(sep)
            if i < 1 or i > len(t):
                return ""
            if len(t) > 1:
                return t[i - 1]
            else:
                return s


        def check(Ip):
            if re.search(regex_IP, Ip):
                return True
            else:
                return False


        def check_interface(interface):
            interface_addrs = psutil.net_if_addrs().get(interface) or []
            return socket.AF_INET in [snicaddr.family for snicaddr in interface_addrs]


        def getnmapresults(subnet, network_prefix, result):
            self.text_result.insert("3.0", "[-] getnmapresults(" + subnet + ", " + str(network_prefix) + "):\n")
            cmdstring = "nmap -sn " + subnet + "/" + str(network_prefix)
            self.text_result.insert("4.0", "[-] " + cmdstring + " \n")
            res2 = Popen(
                cmdstring, shell=True, stdout=PIPE, universal_newlines=True
            ).communicate()[0]
            t_res2 = res2.split("\n")
            tag = "Nmap scan report for"
            ltag = len(tag)
            i = 1
            while i < (len(t_res2) - 2):
                Field5 = StringField(t_res2[i], " ", 5)
                Field6 = StringField(t_res2[i], " ", 6)
                if Field6 != "":
                    Name = Field5
                    IP = StringField(StringField(Field6, "(", 2), ")", 1)
                else:
                    Name = ""
                    IP = Field5
                if t_res2[i + 2].find("MAC Address") != -1:
                    MacAddress = StringField(t_res2[i + 2], " ", 3)
                    MacAddressType = StringField(StringField(t_res2[i + 2], "(", 2), ")", 1)
                    result.append(IP + "\t" + Name + "\t" + MacAddress + "\t" + MacAddressType)
                else:
                    result.append(IP + "\t" + Name)
                    i = i - 1
                i = i + 3


        def show_results(result):
            result.sort()
            for i in range(len(result)):
                if i > 0:
                    if result[i] != result[i - 1]:
                        self.text_result.insert("5.0", str(result[i]) + "\n")
                else:
                    self.text_result.insert("5.0", str(result[i]) + "\n")

        def get_all_adapaters_response(result):
            adapters = ifaddr.get_adapters()

            for adapter in adapters:
                flg = True
                flgup = False
                for sip in adapter.ips:
                    if flg:
                        if check_interface(sip.nice_name):
                            flgup = True
                        else:
                            flgup = False
                        # print('----------------')
                        flg = False
                    if len(sip.ip) != 3:
                        ip = StringIPv4ToIPv4(sip.ip)
                        mask = 4294967295 << (
                            32 - sip.network_prefix
                        )
                        self.text_result.insert("1.0", "[-] ip : " + sip.ip + "\t" + "mask" + str(mask) + "\n")
                        subnet = IPv4ToStringIPv4(ip & mask)
                        if (
                            flgup
                            and StringField(subnet, ".", 1) != "169"
                            and StringField(subnet, ".", 1) != "127"
                        ):
                            getnmapresults(subnet, sip.network_prefix, result)

        try:
            if req == "all" or req == "All":
                result = ([]) 
                get_all_adapaters_response(result)
                show_results(result)
            elif req == "help" or req == "?":
                self.text_result.insert("1.0", "[-] All or all , run nmap on the subnets of all active network cards ! \n")
                self.text_result.insert("2.0", "[-] ? or help , displays this help ! \n")
                self.text_result.insert("3.0", "[-] xxx.xxx.xxx.xxx/yy\n")
                self.text_result.insert("4.0", "[-] Run nmap for the applicable subnet with the mentioned IP and prefix ! \n") 
            elif check(StringField(req, "/", 1)):
                result = []
                prefix = int(StringField(req, "/", 2))
                getnmapresults(
                    IPv4ToStringIPv4(
                        StringIPv4ToIPv4(StringField(req, "/", 1))
                        & (4294967295 << (32 - prefix))
                    ),
                    int(StringField(req, "/", 2)),
                    result,
                )
                show_results(result)

        except socket.gaierror:
            tk.messagebox.showerror(title="ERROR ! ", message="ERROR ! ")



if __name__ == "__main__":
    fen = Window()
    fen.title("SCANNER NETWORK & NMAP GUI")
    fen.geometry("500x600")
    fen.resizable(False, False)
    fen.mainloop()
