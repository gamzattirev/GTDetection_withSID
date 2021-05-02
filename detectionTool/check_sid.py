from evtx import PyEvtxParser
import json
import re
import const
import glob
import sys
import csv

sidlist = {}
with open(const.SID_LIST, 'r') as file:
    for row in file:
        list = row.split()
        sid = list[len(list) - 1]
        accoutname = list[0].lower()
        # print(accoutname,sid)
        sidlist[accoutname] = sid.lower()


adminlist=[]

inputdir=sys.argv[1]
files = glob.glob(inputdir + "/*.evtx")

for file in files:

    parser = PyEvtxParser(file)

    for record in parser.records_json():
        data = json.loads(record['data'])
        event_id=data['Event']['System']['EventID']
        if event_id == const.EVENT_PRIV:
            accountname = data['Event']['EventData']['SubjectUserName'].lower()
            #print(accountname)
            adminlist.append(accountname)
            continue

        if  event_id== const.EVENT_LOGIN or event_id== const.EVENT_LOGIN_FAIL:
            sid=data['Event']['EventData']['TargetUserSid'].lower()
            accountname=data['Event']['EventData']['TargetUserName'].lower()
            #print(sid+','+accountname)

            # if sid is not domain SID, exclude from detection
            pattern = 's\-[0-9]+\-'
            result = re.match(pattern, sid)
            if result:
                sid_list = sid.split('-')
                if len(sid_list)<7:
                     continue

            # if accounname or sid is not recorded, exclude from detection
            # if sid is system, exclude from detection
            if accountname == '-' or sid == 'NULL SID':
                continue
            try:
                # accountname does not match sid
                if accountname != sid:
                    # compare accountname and sid using master DB
                        # accountname and sid exsist in master DB
                    sid_db=''
                    if accountname in sidlist:
                        sid_db=sidlist[accountname]
                    if sid_db==sid:
                        continue

                    # accountname does not exist but sid exsist in master DB
                    if sid in sidlist.values():
                        print(const.RESULT_SID_MISMATCH + "sid:" + sid + ", account:" + accountname)

                    # accountname and sid does not exsist in master DB
                    # check whether account has domain admin privilage
                    if accountname not in adminlist:
                        # account does not have admin privilage
                        continue

                    print(const.RESULT_SID_MISMATCH+"sid:"+sid+", account:"+accountname)
                else:
                    continue
            except Exception as e:
                file = open('err.log', 'a')
                file.write(str(e))
