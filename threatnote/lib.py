'''
Library of functions called by different modules
'''
from flask import jsonify
from flask_login import current_user
import re
import json
from config import db
from models import Comments, User, Organization, Indicators, Links
from sqlalchemy import func, asc, desc
from datetime import datetime
import json
import requests

IP_REGEX = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
DOMAIN_REGEX = r'(?:(?:[\da-zA-Z])(?:[_\w-]{,62})\.){,127}(?:(?:[\da-zA-Z])[_\w-]{,61})?(?:[\da-zA-Z]\.(?:(?:xn\-\-[a-zA-Z\d]+)|(?:[a-zA-Z\d]{2,})))'
EMAIL_REGEX = r'\S+@\S+\.\S+'
SHA_REGEX = r'[A-Fa-f0-9]{64}'
SHA512_REGEX = r'[A-Fa-f0-9]{128}'
MD5_REGEX = r'[A-Fa-f0-9]{32}'
ATTACK_REGEX = r'T\d{4}'
URL_REGEX = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
CVE_REGEX = r'CVE\-\d{4}\-\w+'

def add_db_entry(entry):
    db.session.add(entry)
    db.session.flush()
    db.session.commit()

'''
sends a webhook to a list of urls
'''
def send_webhook(message, urls=[]):
    for url in urls:
        if isinstance(message,dict):
            wh_data = message
        else:
            wh_data={'text': message}

        try:
            response = requests.post(
                url, json.dumps(wh_data),
                headers={'Content-Type': 'application/json'}
                )
            if response.status_code != 200:
                print('Webhook error sending message "{}" to url {}. Response code: {} Response text: {}'.format(wh_data,url,response.status_code, response.text))
            else:
                print('Webhook sent to {}. {}'.format(url,wh_data))
        except Exception as err:
            print('Webhook error sending message "{}" to url {}. {}'.format(wh_data,url,err))
'''
returns a list of comments dicts
'''
def get_comments(req_id=None, report_id=None, indicator_id=None):   
    comments=[]
    if report_id:
        comments=(db.session.query(Comments, User.name)
                  .join(User, User.id==Comments.user)
                  .filter(Comments.report==report_id)
                  .order_by(desc(Comments.updated_at))#desc()
                  .all()
                  )

    if indicator_id:
        comments=(db.session.query(Comments, User.name)
                  .join(User, User.id==Comments.user)
                  .filter(Comments.indicator==indicator_id)
                  .order_by(desc(Comments.updated_at))#desc()
                  .all()
                  )

    if req_id:
        comments=(db.session.query(Comments, User.name)
                  .join(User, User.id==Comments.user)
                  .filter(Comments.requirement==req_id)
                  .order_by(desc(Comments.updated_at))#desc()
                  .all()
                  )
    return [{'id':comm.id, 'comment':comm.comment, 'created_at':comm.created_at, 'updated_at':comm.updated_at, 'user':user} for comm, user in comments]
'''
returns info on user
'''
def get_user_info(id):
    user_info={}
    user, org=(db.session.query(User, Organization)
               .join(Organization, Organization.id==User.organization)
               .filter(User.id==id).first())
    if user:
        user_info=user.__dict__
        #no urlscan key checking for now???
        user_info['whois_enabled']=org.whois_enabled
        user_info['ipinfo_enabled']=org.ipinfo_enabled
        
        user_info['vt_enabled']=org.vt_enabled
        user_info['shodan_enabled']=org.shodan_enabled
        user_info['emailrep_enabled']=org.emailrep_enabled
        user_info['av_enabled']=org.av_enabled
        user_info['gn_enabled']=org.gn_enabled
        user_info['riskiq_enabled']=org.riskiq_enabled
        user_info['urlscan_enabled']=org.urlscan_enabled
        user_info['misp_enabled']=org.misp_enabled
        user_info['hibp_enabled']=org.hibp_enabled
        user_info['hunter_enabled']=org.hunter_enabled

        if user.role=='admin':
            user_info['vt_api_key']=org.vt_api_key
            user_info['shodan_api_key']=org.shodan_api_key
            user_info['emailrep_api_key']=org.emailrep_api_key
            user_info['av_api_key']=org.av_api_key
            user_info['gn_api_key']=org.gn_api_key
            user_info['riskiq_api_key']=org.riskiq_api_key
            user_info['riskiq_username']=org.riskiq_username
            user_info['urlscan_api_key']=org.urlscan_api_key
            user_info['misp_api_key']=org.misp_api_key
            user_info['misp_url']=org.misp_url
            user_info['hibp_api_key']=org.hibp_api_key
            user_info['hunter_api_key']=org.hunter_api_key
        #print(user_info)
    return user_info



'''
returns 
minutes ago if < hour
hours ago if < day
days ago if < week
weeks ago if < month
months ago if < year
else years ago
'''
def time_ago(time):
    diff_seconds=(datetime.now() - time).total_seconds()
    MINUTE=60
    HOUR=MINUTE*60
    DAY=HOUR*24
    WEEK=DAY*7
    MONTH=DAY*30
    YEAR=DAY*365
    
    if diff_seconds < MINUTE:
        return ('Just now')
    elif diff_seconds < HOUR:
        if diff_seconds/MINUTE ==1:
            return '1 minute ago'
        else:
            return '{0:.0f} minutes ago'.format(diff_seconds/MINUTE)
    elif diff_seconds < DAY:
        if round(diff_seconds/HOUR) ==1:
            return '1 hour ago'
        else:
            return '{0:.0f} hours ago'.format(diff_seconds/HOUR)
    elif diff_seconds < WEEK:
        if round(diff_seconds/DAY) ==1:
            return '1 day ago'
        else:
            return '{0:.0f} days ago'.format(diff_seconds/DAY)
    elif diff_seconds < MONTH:
        if round(diff_seconds/WEEK) ==1:
            return '1 week ago'
        else:
            return '{0:.0f} weeks ago'.format(diff_seconds/WEEK)
    elif diff_seconds < YEAR:
        if round(diff_seconds/MONTH) ==1:
            return '1 month ago'
        else:
            return '{0:.0f} months ago'.format(diff_seconds/MONTH)
    else:
        return '{0:.1f} years ago'.format(diff_seconds/YEAR)

'''
Don't create a link for that indicator/report combo already in there - will save on database space
'''
def link_exists(new_link):
    link=Links.query.filter_by(indicator=new_link.indicator).filter_by(report=new_link.report).first()
    
    return link != None

'''
Escape out characters so jquery works
'''
def escape_jquery(value):
    escape_chars='!"#$%&\'()*+,./:;<=>?@[\\]^``{|}~'
    for char in escape_chars:
        value=value.replace(char, '__')
    else:
        return value


'''
parse out the indicators in a report, save record linking indicator to a report, and 
put them in queue to be enriched.
'''
def parse_indicators(summary, report_id, queue):
    ips = re.findall(IP_REGEX,summary)
    domains = re.findall(DOMAIN_REGEX,summary)
    attacks = re.findall(ATTACK_REGEX,summary)
    sha256 = re.findall(SHA_REGEX,summary)
    emails = re.findall(EMAIL_REGEX, summary)   
    md5 = re.findall(MD5_REGEX, summary)  
    sha512 = re.findall(SHA512_REGEX, summary)
    urls = re.findall(URL_REGEX, summary)
    cve = re.findall(CVE_REGEX, summary)
    
    org_id=User.query.filter_by(id=current_user.id).first().organization
    
    
    #get a list of indicator ids to link to report
    indicator_ids={}
    
    for match in ips:
        match_check = Indicators.query.filter_by(indicator=match).first()
        if match_check:
           indicator_ids[match_check.id]=match
        else:
            # Indicator doesn't exist, create new indicator and link
            new_indicator = Indicators(indicator=match,indicator_type='IP')
            add_db_entry(new_indicator)
            indicator_ids[new_indicator.id]=match 

    for match in urls:
        match_check = Indicators.query.filter_by(indicator=match).first()
        if match_check:
           indicator_ids[match_check.id]=match
        else:
            # Indicator doesn't exist, create new indicator and link
            new_indicator = Indicators(indicator=match,indicator_type='URL')
            add_db_entry(new_indicator)
            indicator_ids[new_indicator.id]=match 
    
    for match in md5:

        match_check = Indicators.query.filter_by(indicator=match).first()
        if match_check:
           indicator_ids[match_check.id]=match
        else:
            # Indicator doesn't exist, create new indicator and link
            new_indicator = Indicators(indicator=match,indicator_type='MD5 Hash')
            add_db_entry(new_indicator)
            indicator_ids[new_indicator.id]=match 

    for match in domains:
        #so don't do as a domain if an email address
        if match not in emails + ips + urls:
            match_check = Indicators.query.filter_by(indicator=match).first()
            if match_check:
                indicator_ids[match_check.id]=match
            else:
                # Indicator doesn't exist, create new indicator and link
                new_indicator = Indicators(indicator=match,indicator_type='Domain')
                add_db_entry(new_indicator)
                indicator_ids[new_indicator.id]=match 
        
    for match in attacks:
        match_check = Indicators.query.filter_by(indicator=match).first()
        if match_check:
            indicator_ids[match_check.id]=match
        else:
            # Indicator doesn't exist, create new indicator and link
            new_indicator = Indicators(indicator=match,indicator_type='MITRE ATT&CK Technique')
            add_db_entry(new_indicator)
            indicator_ids[new_indicator.id]=match 
        
    for match in sha256:
        match_check = Indicators.query.filter_by(indicator=match).first()
        if match_check:
            indicator_ids[match_check.id]=match
        else:
            # Indicator doesn't exist, create new indicator and link
            new_indicator = Indicators(indicator=match,indicator_type='SHA256 Hash')
            add_db_entry(new_indicator)
            indicator_ids[new_indicator.id]=match 

    for match in sha512:
        match_check = Indicators.query.filter_by(indicator=match).first()
        if match_check:
            indicator_ids[match_check.id]=match
        else:
            # Indicator doesn't exist, create new indicator and link
            new_indicator = Indicators(indicator=match,indicator_type='SHA512 Hash')
            add_db_entry(new_indicator)
            indicator_ids[new_indicator.id]=match 

    for match in emails:
        match_check = Indicators.query.filter_by(indicator=match).first()
        if match_check:
            indicator_ids[match_check.id]=match
        else:
            # Indicator doesn't exist, create new indicator and link
            new_indicator = Indicators(indicator=match,indicator_type='Email')
            add_db_entry(new_indicator)
            indicator_ids[new_indicator.id]=match 

    for match in cve:
        match_check = Indicators.query.filter_by(indicator=match).first()
        if match_check:
            indicator_ids[match_check.id]=match
        else:
            # Indicator doesn't exist, create new indicator and link
            new_indicator = Indicators(indicator=match,indicator_type='CVE')
            add_db_entry(new_indicator)
            indicator_ids[new_indicator.id]=match 

    #consolidated all this down here    
    for id in indicator_ids:
        match=indicator_ids[id]
        # Kickoff a task to enrich the new indicator
        job = queue.enqueue('main.enrich_pipeline', json.dumps({'indicator': str(match),'organization':org_id}))
        new_link=Links(indicator=id, report=report_id,kill_chain='Unknown',diamond_model='Unknown',confidence='Low')
        if not link_exists(new_link):
            add_db_entry(new_link)
