
import os
import re
import ipaddress
import subprocess

import pystray
import PIL.Image
import threading

from tkinter import messagebox

import smtplib
from twilio.rest import Client
from windows_toasts import WindowsToaster, ToastText1

import tkinter

from tkinter import *
from tkinter import ttk
from netmiko import ConnectHandler
from scapy.all import Ether, ARP, srp, conf

paused = True

online_ip = []
arp_table = []
v_address = []
temp = []
_time_request = []
notify_once = 0

subject = f'Warning !!! Insider network attack'
email = 'arpmyprojects@gmail.com'
password = 'cctlaxajgwttqiwx'
email_sent = 'arpmyprojects@gmail.com'



'''   -----------------     Build ARP Cache   -------------------  '''

def my_subnet():
    pkt = Ether()/ARP()
    str_pkt = str(pkt.psrc)
    list_pkt = str_pkt.split(".")
    list_pkt.pop()
    str_pkt = ".".join(list_pkt)
    str_pkt += '.0/24'
    return str_pkt

def my_ip():
    pkt = Ether()/ARP()
    return str(pkt.psrc)

# Network address
net_addr = my_subnet()

# Create the network
ip_net = ipaddress.ip_network(net_addr)

# Get all hosts on that network
all_hosts = list(ip_net.hosts())

# Configure subprocess to hide the console window
info = subprocess.STARTUPINFO()
info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
info.wShowWindow = subprocess.SW_HIDE

# For each IP address in the subnet, 
# run the ping command with subprocess.popen interface
def ping_all_hosts():
    host_count = 0
    for i in range(len(all_hosts)):
        output = subprocess.Popen(['ping', '-n', '1', '-w', '500', str(all_hosts[i])], stdout=subprocess.PIPE, startupinfo=info).communicate()[0]
        if host_count > 20:
            break
        if "Destination host unreachable" in output.decode('utf-8'):
            host_count += 1
        elif "Request timed out" in output.decode('utf-8'):
            host_count += 1
        else:
            online_ip.append(str(all_hosts[i]))

def get_arp_cache():
    arpt = []
    # Get data from 'arp -a'
    with os.popen('arp -a') as f:
        data = f.read()
    for line in re.findall('([-.0-9]+)\s+([-0-9a-f]{17})\s+(\w+)',data):
        s = str(line)
        s = s.replace("'", "")
        s = s.replace("(", "")
        s = s.replace(")", "")
        s = s.replace("-", ":")
        list_s = s.split(", ")
        list_s.pop()
        s = ",".join(list_s)
        for i in online_ip:
            if str(i + ",") in s:
                arpt.append(s)
    # Add this device's address to arp table 
    arpt.append(get_my_address())
    # Filter out duplicate elements and sort the arp table
    s = set(arpt)
    arpt = list(s)
    arpt.sort()
    return arpt

# Get this device's address
def get_my_address():
    pkt = Ether()/ARP()
    ip_add = str(pkt.psrc)
    mac_add = str(pkt.hwsrc)
    return ip_add + "," + mac_add

def get_local_devices():
    # Create an ARP request packet
    temp = []
    arp = ARP(pdst = my_subnet()) # Change to your network's subnet
    ether = Ether(dst='ff:ff:ff:ff:ff:ff')
    packet = ether/arp

    # Send the packet and get a list of responses
    result = srp(packet, timeout=3, verbose=0)[0]

    # Extract the IP and MAC addresses from the responses
    for sent, received in result:
        temp.append(f'{received.psrc},{received.hwsrc}')
        temp.sort()
    return temp

def _reset_Arp_cache():
	ping_all_hosts()
	return get_arp_cache()

'''  ----------------------     Notification (Thông báo)   ----------------------'''


def email_notice(ipadd, mac_attacker):

    session = smtplib.SMTP('smtp.gmail.com', 587)
    session.starttls() # enalble security
    session.login(email, password)

    content =  f'Waring !!! IP :{ipadd} has a MAC address is: {mac_attacker}. There is a threat status to LAN Network !'

    mail_content = f'Subject: {subject}\n\n{content}'

    session.sendmail(email, email_sent, mail_content)


def log_notice():
	wintoaster = WindowsToaster('Warning !!!')
	newToast = ToastText1()
	newToast.SetBody('Inside attack network')
	# newToast.on_activated = lambda _: print('Toast clicked!')
	wintoaster.show_toast(newToast)


def sms_notice():
	account_sid = "ACa7cfe4fb06139f94e34dea989908127b"
	auth_token = "376fc90d7cbfb79fc3f1c55438ccbe17"
	client = Client(account_sid, auth_token)

	message = client.messages.create(
		body="Warning !!! Insider network attack",
		from_="+17328511621",
		to="+84383459354"
	)


'''  ----------------------     Port Disable (Chan port)   ----------------------'''

network_device = {
    "host": "192.168.10.2",
    "username": "admin",
    "password": "123",
    "device_type": "cisco_ios",
    "secret": "123"
}


connect_device = ConnectHandler(**network_device)
connect_device.enable()


def get_port_from_ip_mac(mac_attacker):

    command = f'show mac address-table | include {mac_attacker}'
    output = connect_device.send_command(command)

    # Parse the output to get the port number
    if output:
        port = output.split()[-1]
        print('The MAC address', mac_attacker, 'is on port', port)
        return port
    else:
        print('The MAC address', mac_attacker, 'is not found')

# Disconnect from the switch

def disable_a_port(port):
    global notify_once
    notify_once = 0

    list_of_commands = ["interface " + str(port), " shut"]

    print("------------------------------------Status------------------------------------")
    to_execute = connect_device.send_command("show interface " + str(port) + " status")
    print(to_execute)

    print("-----------------------------------Commands-----------------------------------")
    to_execute = connect_device.send_config_set(list_of_commands)
    print(to_execute)

    print("--------------------------------------------Status--------------------------------------------")
    to_execute = connect_device.send_command("show interface " + str(port) + " status")
    print(to_execute)


'''  ------------     MAC Scaning (Quét địa chỉ MAC và phát cảnh báo khi bị tấn công)   -----------'''

def find_IP_attacker():
    if len(v_address) != 0:
        print("Finding the attacker")
        for i in range(len(temp)):
            [ipadd, MAC] = temp[i].split(',')
            if v_address[1] == MAC and v_address[0] != ipadd:
                return ipadd


def mac_scaning(ipadd, mac_address):
    arp_request = ARP(pdst = ipadd)
    broadcast_adr = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_br = broadcast_adr/arp_request
    list_add = srp(arp_req_br, timeout = 3, verbose=0)[0]
    list_add.sort()
    for sent, received in list_add:
        if received is None:
            return 'None'
        elif received.hwsrc == mac_address:
            return f'[INFO]: {ipadd} has MAC is {received.hwsrc} - Safe'
        elif received.hwsrc != mac_address:
            v_address.append(ipadd)
            v_address.append(mac_address)
            global notify_once
            if notify_once == 0:
                log_notice()
                sms_notice()
                email_notice(find_IP_attacker(),mac_address)
                notify_once = 1
            return f'[WARNING]: {ipadd} has MAC is {mac_address} - Warning'
            


'''  ----------------------     Giao diện (Thiết kế giao diện chương trình)   ----------------------'''


def _arp_cache():
	_table_frame = tkinter.LabelFrame(frame)
	_table_frame.grid(row = 3, column = 0, sticky = "news", padx = 20, pady = 20)

	_table_exe = tkinter.Label(_table_frame)
	_table_exe.grid(row = 0, column = 0)

	table_arp = ttk.Treeview(_table_frame)
	table_arp.grid(row = 0, column = 0)

	table_arp['columns'] = ('IP', 'MAC')

	table_arp.column('#0', width = 0, stretch = NO)
	table_arp.column('IP', anchor = CENTER, width = 300)
	table_arp.column('MAC', anchor = CENTER, width = 300)

	table_arp.heading("#0", text = "", anchor = CENTER)
	table_arp.heading("IP", text = "Internet Address", anchor = CENTER)
	table_arp.heading("MAC", text = "Physical Address", anchor = CENTER)


	for i in range(len(temp)):
		[ipadd, MAC] = temp[i].split(',')
		table_arp.insert(parent='',index='end',iid = i,text='',
			values = (ipadd, MAC))

def _reset_arp():
	arp_table = _reset_Arp_cache()
	temp.clear()
	for i in range(len(arp_table)):
		temp.append(arp_table[i])
	return _arp_cache()


def default_table():
	_table_frame = tkinter.LabelFrame(frame)
	_table_frame.grid(row = 3, column = 0, sticky = "news", padx = 20, pady = 20)

	_table_exe = tkinter.Label(_table_frame)
	_table_exe.grid(row = 0, column = 0)

	table_arp = ttk.Treeview(_table_frame)
	table_arp.grid(row = 0, column = 0)

	table_arp['columns'] = ('IP', 'MAC')

	table_arp.column('#0', width = 0, stretch = NO)
	table_arp.column('IP', anchor = CENTER, width = 300)
	table_arp.column('MAC', anchor = CENTER, width = 300)

	table_arp.heading("#0", text = "", anchor = CENTER)
	table_arp.heading("IP", text = "Internet Address", anchor = CENTER)
	table_arp.heading("MAC", text = "Physical Address", anchor = CENTER)


	for i in range(len(temp)):
		[ipadd, MAC] = temp[i].split(',')
		table_arp.insert(parent='',index='end',iid = i,text='',
			values = (ipadd, MAC))

	reset_cache = tkinter.LabelFrame(frame)
	reset_cache.grid(row = 4, column = 0)

	_MAC_scan = tkinter.Button(reset_cache, text='Refresh', command = _reset_arp)
	_MAC_scan.grid(row = 0, column = 0)


def _mac_security():

	_table_frame = tkinter.LabelFrame(frame)
	_table_frame.grid(row = 3, column = 0, sticky = "news", padx = 20, pady = 20)

	_entry_count = tkinter.Entry(_table_frame)
	_entry_count.config(width = 20)

	_table_exe = tkinter.Label(_table_frame)
	_table_exe.grid(row = 0, column = 0)

	table_arp = ttk.Treeview(_table_frame)
	table_arp.grid(row = 0, column = 0)

	table_arp['columns'] = ('details', 'status')

	table_arp.column('#0', width = 0, stretch = NO)
	table_arp.column('details', anchor = CENTER, width = 500)
	table_arp.column('status', anchor = CENTER, width = 100)

	table_arp.heading("#0", text = "", anchor = CENTER)
	table_arp.heading("details", text = "Details", anchor = CENTER)
	table_arp.heading("status", text = "Status", anchor = CENTER)
	
	for i in range(len(temp)):
            [ipadd, MAC] = temp[i].split(',')
            v_address = mac_scaning(ipadd, MAC)
            if v_address == None:
                v_address = f'[INFO]: IP {ipadd} no reply - None'
            [detail,status] = v_address.split(' - ')
            table_arp.insert(parent='',index='end',iid = i,text='',
                             values = (detail, status))

def _port_security():
	_table_frame = tkinter.LabelFrame(frame)
	_table_frame.grid(row = 3, column = 0, sticky = "news", padx = 20, pady = 20)

	_table_exe = tkinter.Label(_table_frame)
	_table_exe.grid(row = 0, column = 0)

	table_arp = ttk.Treeview(_table_frame)
	table_arp.grid(row = 0, column = 0)

	table_arp['columns'] = ('details', 'port')

	table_arp.column('#0', width = 0, stretch = NO)
	table_arp.column('details', anchor = CENTER, width = 500)
	table_arp.column('port', anchor = CENTER, width = 100)

	table_arp.heading("#0", text = "", anchor = CENTER)
	table_arp.heading("details", text = "Attacker details", anchor = CENTER)
	table_arp.heading("port", text = "Port", anchor = CENTER)
	[_1,_2,_3,_4,_5,_6] = v_address[1].split(":",5)
	mac_toPort = _1+_2+"."+_3+_4+"."+_5+_6
	port = get_port_from_ip_mac(mac_toPort)
	
        #disconnect the attacker
	disable_a_port(port)

	address_attack = f'IP: {find_IP_attacker()} has MAC at {v_address[1]}'
	table_arp.insert(parent='',index='end',iid = 0,text='',
		values = (address_attack, port))

    

def validate_input(new_value):
    if new_value.isdigit() or new_value == "":
        return True
    else:
        return False

def _reset_scan_Cache():
    _reset_arp()
    for i in range(len(temp)):
        [ipadd, MAC] = temp[i].split(',')
        mac_scaning(ipadd,MAC)  




def run():
    image = PIL.Image.open('_logo_AI.ico')
    icon = pystray.Icon('example', image, 'Example')
    icon.run(setup)

def setup(icon):
    # Hàm xử lý khi click vào icon
    def on_clicked(icon, item):
        icon.visible = False

    def show_window():
        icon.visible = False
        window.deiconify()

    # Thêm menu cho icon
    menu = pystray.Menu(
        pystray.MenuItem('Quit', on_clicked),
        pystray.MenuItem('Show', lambda icon, item: show_window())
    )
    icon.menu = menu

    # Hiển thị icon
    icon.visible = True

    # Hàm xử lý sự kiện khi ấn nút OK
    def on_ok_clicked():
        if checkbox_var.get() == 1:  # Kiểm tra trạng thái của checkbox
            window.withdraw()  # Ẩn cửa sổ
            icon.visible = True  # Hiển thị icon
    def on_closing():
        if messagebox.askokcancel("Keep runing", "Run in background??"):
            window.withdraw()
            icon.visible = True

    def countdown(n, count = 0):
        if n >= 0 and not paused:
            _note_input = Label(_input_frame, text=" The program is running..., time scan: "+str(n) + " second. ", font=('calibri', 10,'bold'))
            _note_input.grid(row = 0, column = 2) 
            _note_input.after(1000, countdown, n-1, count+1)
        elif paused:
            temp = count
            if temp > 0:
                countdown(temp-1, count = 0)
        elif n < 0:
            _reset_scan_Cache()
            temp = count
            if temp > 0:
                countdown(temp-1, count = 0)  

    def get_input():
        input_text = input_box.get()
        if input_text == '':
            pass
        elif int(input_text) < 10:
            input_box.delete(0,END)
            _note_input = Label(_input_frame, text="The circulatory time needs more than 30 seconds.", font=('calibri', 10,'bold'))
            _note_input.grid(row = 0, column = 2)
        else:
            on_ok_clicked()
            input_box.config(state = 'disabled')
            number = int(input_text)
            return number


    def toggle_pause():
        global paused
        paused = not paused
        if paused:
            _get_input.config(text="Start")
            _note_input = Label(_input_frame, text="Test cycle time ( Please !!! Enter your a number ).", font=('calibri', 10,'bold'))
            _note_input.grid(row = 0, column = 2)
            input_box.config(state = 'normal')
        else:
            if get_input() is None :
                pass
            else:
                _get_input.config(text="Pause")
                countdown(get_input())

    default_table()

    event_click = tkinter.LabelFrame(frame, text = "Module")
    event_click.grid(row = 0, column = 0)

    _arp_table = tkinter.Button(event_click, text='ARP Cache', command = default_table)
    _arp_table.grid(row = 0, column = 0)

    _MAC_scan = tkinter.Button(event_click, text='MAC Scan', command = _mac_security)
    _MAC_scan.grid(row = 0, column = 1)

    _port_disable = tkinter.Button(event_click, text='Warning Port', command = _port_security)
    _port_disable.grid(row = 0, column = 2)

    for widget in event_click.winfo_children():
        widget.grid_configure(padx = 10, pady = 5)

    input_value = StringVar()

    checkbox_var = tkinter.IntVar()
    _on_box = tkinter.Checkbutton(frame, text='Hide programs under taskbar.', variable=checkbox_var)
    _on_box.grid(row = 2, column = 0)

    _input_frame = tkinter.LabelFrame(frame)
    _input_frame.grid(row = 1, column = 0, padx = 20, pady = 20)
    _input_frame.configure(borderwidth=0)

    input_box = Entry(_input_frame, textvariable=input_value, validate="key", width = 10)
    input_box.config(validatecommand=(input_box.register(validate_input), '%P'))
    input_box.grid(row = 0, column = 0, padx = 10,pady = 5)

    _get_input = Button(_input_frame, text="Start", command = toggle_pause)
    _get_input.grid(row = 0, column = 1)

    _note_input = Label(_input_frame, text="Test cycle time ( Please !!! Enter your a number ).", font=('calibri', 10,'bold'))
    _note_input.grid(row = 0, column = 2)

    window.protocol("WM_DELETE_WINDOW", on_closing)




if __name__ == '__main__':
    window = tkinter.Tk()
    window.title("Inside Security Network - ISN")
    window.iconbitmap('_logo_AI.ico')
    window.geometry('700x500+400+200')

    frame = tkinter.Frame(window)
    frame.pack()
    threading.Thread(target=run).start()


    window.mainloop()
