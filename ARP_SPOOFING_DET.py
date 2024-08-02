
from scapy.all import *
#import scapy.all as scapy
from datetime import datetime

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
def send_email(subject, message):
    # Sender and receiver email addresses
    sender_email = "sender@domain.com"
    receiver_email = "receiver@domain.com"
    # Email server credentials
    # We used gmail smtp servers, use your respective use case 
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    smtp_username = "sender@domain.com"
    smtp_password = "*Insert Password*"

    # Create a MIMEText object to represent the email body
    email_body = MIMEText(message)

    # Create a MIMEMultipart object to represent the email
    email_message = MIMEMultipart()
    email_message["From"] = sender_email
    email_message["To"] = receiver_email
    email_message["Subject"] = subject

    # Attach the email body to the email message
    email_message.attach(email_body)
    print("Sending email...")

    # Connect to the SMTP server
    try:
       server = smtplib.SMTP("smtp.gmail.com", 587)
       server.starttls()
       server.login(smtp_username, smtp_password)
       server.sendmail(sender_email, receiver_email, email_message.as_string())
       print("Email sent to ", receiver_email)
    except:
       print("Error in connecting to SMTP server")

def mac(ipadd):
    arp_request = ARP(pdst=ipadd)
    #print("[*] ALERT!3")

    br = Ether(dst="ff:ff:ff:ff:ff:ff")
    #print("[*] ALERT!4")

    arp_req_br = br / arp_request
    #print("[*] ALERT!5")

    list_1 = srp(arp_req_br, timeout=5, verbose=False)[0]
    #print(list_1)
    if list_1:
 
       return list_1[0][1].hwsrc
    else:
       return None
#originalmac1={"192.168.0.1":"28:80:88:9B:61:5B"}
arp_cache={}
def process_sniffed_packet(packet):
    if packet.haslayer(ARP):
        #print("[*] ALERT!")
        #print(f"Source IP: {packet[ARP].psrc}")
        #print(f"target: {packet[ARP].pdst}")
        ##originalmac = mac(packet[ARP].psrc)
        #print("[*] ALERT!2")
        ##responsemac = packet[ARP].hwsrc
        #print(responsemac)
        #if originalmac != responsemac
         arp_src_ip = packet[ARP].psrc
         arp_src_mac=packet[ARP].hwsrc
         if arp_src_ip in arp_cache:
            if arp_cache[arp_src_ip] != arp_src_mac:
               print("[*] ALERT!! You are under attack, the ARP table is being poisoned.!")
               #print(f"ARP Spoofing Detected in NET92 network, Original MAC: {originalmac}, New MAC: {responsemac} on {datetime.now().strftime('%A')} at {datetime.now()}.")

               subject = "ARP Spoofing!"
               message = f"ARP Spoofing Detected in NET92 network, The New MAC: {arp_src_mac}  on {datetime.now().strftime('%A')} at {datetime.now()}."
               send_email(subject, message)
         arp_cache[arp_src_ip]=arp_src_mac
#elif originalmac == responsemac:
            #print(f"Yu are not under attack OLD: {originalmac} New: {responsemac}")

print("******************* STARTED ***********************************")
sniff(iface="eth0", store=0 ,filter= "arp",  prn=process_sniffed_packet)
