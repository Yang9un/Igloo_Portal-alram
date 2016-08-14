# -*- coding:cp949 -*-
import json
import re
import urllib2
import portal_module
import winsound
import sendmail2
import subprocess
import thread
import time
from datetime import datetime, timedelta

new_event = {}
before_event = {}

#login
def login():
    return portal_module.webesm_login("http://000.000.000.000/siem/login/form", "j_username=0000", "0000")[0]


def result_parsing(data):
    global new_event, pcap, event_time
    global before_event

    if len(data) != 0:
        for idx, i in enumerate(data["continue_data"]):
            # if i["rulename"].find("Injection") != -1:
            event = i["stime"], i["rulename"], i["s_info"], i["d_info"]

#line(dic)에서 pcap추출
            pcap_dic = json.loads(i["line"].replace("true", "1").encode("utf8", "ignore"))
            if 'pcap' in pcap_dic:
                pcap = pcap_dic["pcap"]
                if pcap == "null":
                    pcap = "4e4f4e45"
            else:
                pcap = "4e4f4e45"
#IDS 탐지시간
#            print pcap_dic
            if 'cdtime' in pcap_dic:
                event_time = str(pcap_dic["cdtime"])
                event_time = str(datetime.now().strftime("%Y-%m-%d") + " " + event_time[:8])
                #13:38:35.645
            elif 'event_time' in pcap_dic:
                event_time = str(pcap_dic["event_time"])
                event_time = str(event_time[:4] + "-" + event_time[4:6] + "-" + event_time[6:8] + " " + event_time[8:10] + ":" + event_time[10:12] + ":" + event_time[12:14])

                #20160520134104551
            else:
                event_time = "4e4f4e45"
#            print "IDS TIME : " + event_time
#중복제거 핵심
            if event == before_event:
                before_event = new_event
                break
#mail body 작성
            elif event != before_event:
                if 'xpcap1' in pcap_dic:
                    mailbody = "<pre><br><br><br>[SEC] "+ i["rulename"]+ u"<br>- IDS탐지 : "+ event_time + u"<br>- ESM탐지 : "+ i["stime"].replace("/","-") + " (" + i[u"origin_name"] + u")<br>- 차  단 : " + datetime.now().strftime("%Y-%m-%d") + u"<br>- 출발지 : (" + i["_s_info_icon"].upper() + ") " + i["s_info"] + u"<br>- 목적지 : (" + i["_d_info_icon"].upper() + ") " + i["d_info"]+ "( )("+ i["d_port"]+")<br>" + pcap.replace("<","") + u"<br><br>엑셀 정리내용<br>ACMS					" + event_time + "	" + i["stime"].replace("/","-") + "	" + datetime.now().strftime("%Y-%m-%d") + "	" + i["s_info"] + "	" + i["_s_info_icon"].upper() + "</pre>"
                else:
                    mailbody = "<pre><br><br><br>[SEC] "+ i["rulename"]+ u"<br>- IDS탐지 : "+ event_time + u"<br>- ESM탐지 : "+ i["stime"].replace("/","-") + " (" + i[u"origin_name"] + u")<br>- 차  단 : " + datetime.now().strftime("%Y-%m-%d") + u"<br>- 출발지 : (" + i["_s_info_icon"].upper() + ") " + i["s_info"] + u"<br>- 목적지 : (" + i["_d_info_icon"].upper() + ") " + i["d_info"]+ "( )("+ i["d_port"]+")<br>" + bytearray.fromhex(pcap).decode("utf8","ignore").replace("<","") + u"<br><br>엑셀 정리내용<br>ACMS					" + event_time + "	" + i["stime"].replace("/","-") + "	" + datetime.now().strftime("%Y-%m-%d") + "	" + i["s_info"] + "	" + i["_s_info_icon"].upper() + "</pre>"
#알람 발생
                winsound.PlaySound('portal.wav', winsound.SND_FILENAME)
                winsound.PlaySound('portal.wav', winsound.SND_FILENAME)
                sendmail2.Mail_send(mailbody, "[Portal Alert]" + i["rulename"])
                if before_event == {}:
                    before_event = i["stime"], i["rulename"], i["s_info"], i["d_info"]
                    new_event = i["stime"], i["rulename"], i["s_info"], i["d_info"]
                elif idx == 0:
                    new_event = i["stime"], i["rulename"], i["s_info"], i["d_info"]
                    if len(data["continue_data"]) - 1 == idx:
                        before_event = i["stime"], i["rulename"], i["s_info"], i["d_info"]
                elif len(data["continue_data"]) - 1 == idx:
                    before_event = i["stime"], i["rulename"], i["s_info"], i["d_info"]

                if i["d_port"] == "1433" or i["d_port"] == "3306" or i["d_port"] == "3389":
                    thread.start_new_thread(network_scanning, (i["d_info"], i["stime"], i["rulename"],))
                    time.sleep(1)
        before_event = new_event

#스캔기능
def network_scanning(dst_ip, stime, rulename):
    mail_body = ''
    regex_service = "vpn|pptp|proxy|teamview|irc|vnc|radmin|6667|1723|1194|5938|5900|4899"
    cmd = "nmap -sS -sV -Pn -T 5 --min-parallelism 100 --open " + dst_ip
    p = subprocess.check_output(cmd, shell=False)
    file_name = datetime.now().strftime("%Y%m%d%H%M%S_") + dst_ip.replace(".", "_") + ".log"
    nmap_result = open(file_name, "a")
    nmap_result.write(p)
    nmap_result.close()
    for i in re.findall("[0-9]{1,5}\/tcp.*\r\n", p):
        if re.findall(regex_service, i):
            mail_body += i
    if mail_body != '':
        winsound.PlaySound('port.wav', winsound.SND_FILENAME)
        sendmail2.Mail_send(stime + " - " + rulename + " - " + dst_ip + " suspicious port open\nfile name : " + file_name, "[Portal Alert] " + stime + " " + rulename)

#request & response
def view_alram():
    now = datetime.now()
    timegap = timedelta(hours=24)
    cookie_file = open("cookie_session", "r")
    cookie = login()
    # print cookie
    # url = "http://000.000.000.000/siem/search/alert_search_data.do"
    url = "http://000.000.000.000/siem/analysis/multirule_continue_list.do"
    #url = "http://000.000.000.000/siem/analysis/multirule_continue_list.do"
    #values = {'stime':(now-timegap).strftime("%Y%m%d%H%M00"),'etime':now.strftime("%Y%m%d%H%M00"),'type':'title' ,'continue_limit':'30','end_limit':'30','multi_check':'2','multi_check':'all','filter_multirule':[] ,'filter_simplerule':["10181","10190","10184","9721","9729","10183","9768","9769","9770","9772","9755","9790","9765","9760","9761","9762","9764","9766","10155","10188","9776","9777","9779","9780","9782","9784","9785","9786","9789","9791","9793","9794","9757","9773","9775","9822","9823","9825","9827","9797","9799","9801","9802","9804","9805","9806","9808","9809","9820","9735","10197","9828","9829","9831","10148","10152","18127","10162","10182","10158","10159","10165","10166","10170","10171","10175","10179","10185","10187","10192","10218","10149","10150","10151","10153","10154","10156","10157","10200","10201","10204","10205","10207","10208","10236","10209","10211","10213","10194","10195","10198","10199","10230","10244","10245","10189","10167","10160","10168","10191","10161","10169","10186","10163","10177","10176","10164","10215","10219","10222","10225","10226","10227","10231","10233","10234","10241","10217","10212","9725","9723","9733","10250","10174","10173","10178","10172","10180","10206","10221","18148","18695","18183","10216","18869","18907","18049","10223","10237","10238","10224","9824","10210","18176","9763","9739","18877","9778","9787","9771","9821","18899","9830","9803","9781","10202","18895","18875","18893","18901","18905","18903","18897","9798","9774","9783","10242","10232","18909","9800","10239","10214","18698","10235","10240","10203","10193","18865","18760","18101","18867","18871","18873","10228","10229","10246","10196"]}
    #values = {'stime':(now-timegap).strftime("%Y%m%d%H%M00"),'etime':now.strftime("%Y%m%d%H%M00"),'continue_limit':'30','end_limit':'30','level_check':'2'}
    values = {"multi_check": "2", 'stime': (now - timegap).strftime("%Y%m%d%H%M00"), "end_limit": "50",
              "simple_check": "all",
              "filter_simplerule": ["10181", "10190", "10184", "9721", "9729", "10183", "9768", "9769", "9770", "9772",
                                    "9755", "9790", "9765", "9760", "9761", "9762", "9764", "9766", "10155", "10188",
                                    "9776", "9777", "9779", "9780", "9782", "9784", "9785", "9786", "9789", "9791",
                                    "9793", "9794", "9757", "9773", "9775", "9822", "9823", "9825", "9827", "9797",
                                    "9799", "9801", "9802", "9804", "9805", "9806", "9808", "9809", "9820", "9735",
                                    "10197", "9828", "9829", "9831", "10148", "10152", "18127", "10162", "10182",
                                    "10158", "10159", "10165", "10166", "10170", "10171", "10175", "10179", "10185",
                                    "10187", "10192", "10218", "10149", "10150", "10151", "10153", "10154", "10156",
                                    "10157", "10200", "10201", "10204", "10205", "10207", "10208", "10236", "10209",
                                    "10211", "10213", "10194", "10195", "10198", "10199", "10230", "10244", "10245",
                                    "10189", "10167", "10160", "10168", "10191", "10161", "10169", "10186", "10163",
                                    "10177", "10176", "10164", "10215", "10219", "10222", "10225", "10226", "10227",
                                    "10231", "10233", "10234", "10241", "10217", "10212", "9725", "9723", "9733",
                                    "10250", "10174", "10173", "10178", "10172", "10180", "10206", "10221", "18148",
                                    "18695", "18183", "10216", "18869", "18907", "18049", "10223", "10237", "10238",
                                    "10224", "9824", "10210", "18176", "9763", "9739", "18877", "9778", "9787", "9771",
                                    "9821", "18899", "9830", "9803", "9781", "10202", "18895", "18875", "18893",
                                    "18901", "18905", "18903", "18897", "9798", "9774", "9783", "10242", "10232",
                                    "18909", "9800", "10239", "10214", "18698", "10235", "10240", "10203", "10193",
                                    "18865", "18760", "18101", "18867", "18871", "18873", "10228", "10229", "10246",
                                    "10196"], "filter_multirule": [], "type": "title", "continue_limit": "50",
              'etime': now.strftime("%Y%m%d%H%M00")}
    headers = {'Cookie': 'JSESSIONID=' + cookie,
               'Content-Type': 'application/json; charset=UTF-8',
               'Accept-Encoding': 'gzip, deflate'
               }
    #    print headers
    #    print values
    #    print "--------------------------------"
    #    print json.dumps(values)
    req = urllib2.Request(url, json.dumps(values), headers)
    #    print req
    try:
        response = urllib2.urlopen(req, timeout=10)
        #        print response
        esm_result = json.loads(response.read())
        #        print "esm_result : " + esm_result
        result_parsing(esm_result)
    #        print "result_parsing : " + esm_result
    except Exception, e:
        print "exception ", e
        view_alram()

#main
def main():
    while (1):
        before_time = datetime.now()
#        print before_time
#        print datetime.now()
        print "loop strart"
        view_alram()
        if int((datetime.now() - before_time).seconds) < 60:
            print int((datetime.now() - before_time).seconds)
            sleep_time = 60 - int((datetime.now() - before_time).seconds)
            print sleep_time
            time.sleep(sleep_time)
        else:
            sleep_time = 0
        print "loop end, sleep %d time." % sleep_time


if __name__ == '__main__':
    main()