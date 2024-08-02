from scapy.all import *
from datetime import datetime

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# SSID to monitor
target_ssid = "NET92"
def send_email(subject, message):
    # Sender and receiver email addresses
    sender_email = "sender@gmail.com"
    receiver_email = "receiver@gmail.com"
    # Email server credentials
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    smtp_username = "sender@gmail.com"
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


# List to store seen MAC addresses
mac_addresses = []

# Function to handle packet sniffing
def packet_handler(packet):
    
            if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 0x00:  # Association Response (Client associated)
                # Extract the source MAC address from the packet
                ssid = packet.info.decode()
                if ssid == target_ssid:
                    src_mac = packet.addr2
                # Check for MAC spoofing
                    if src_mac in mac_addresses:
                        #print("MAC Spoofing Detected in NET92 network:", src_mac)
                        print(f"MAC Spoofing Detected in NET92 network, MAC:  {src_mac} on {datetime.now().strftime('%A')} at {datetime.now()}.")

                        subject = "MAC Spoofing!"
                        message = f"MAC Spoofing Detected in NET92 network, MAC:  {src_mac} on {datetime.now().strftime('%A')} at {datetime.now()}."
                        send_email(subject, message)

                    else:
                        mac_addresses.append(src_mac)
                        print("MAC:" , src_mac, " connected")

# Start sniffing Wi-Fi packets on the ALFA interface in monitor mode
print("******************* STARTED ***********************************")
sniff(iface="wlx00c0ca990e14", prn=packet_handler, store=0)
