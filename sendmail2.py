# -*- coding:cp949 -*-
import smtplib
from email.mime.text import MIMEText
from email.MIMEMultipart import MIMEMultipart
from email.header import Header

def Mail_send(text, title):
    recipients = [line.strip() for line in open("mail_receiver.txt","r")]    
    COMMASPACE = ", "
    msg = MIMEMultipart("alternative")
    msg["From"] = 'Portal_Alert@0000.com'
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = Header(s=title, charset="utf-8")
    msg.attach(MIMEText(text, "html", _charset="utf-8"))

    smtp = smtplib.SMTP("owa.0000.com")
    smtp.sendmail('Portal_Alert@0000.com', recipients, msg.as_string())
    smtp.close()