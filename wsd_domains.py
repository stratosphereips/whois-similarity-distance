#!/usr/bin/env python
import Levenshtein
from datetime import datetime, timedelta
from tld import get_tld
import pprint as pp
import pythonwhois
from pythonwhois.shared import WhoisException
from contextlib import contextmanager
from collections import Iterable
from passivetotal.common.utilities import is_ip
from texttable import Texttable
from _version import __version__
import re
from passivetotal.libs.whois import *
import dateutil.parser
import numpy as np
import sys
import argparse
import os
import json
import time
import warnings

warnings.filterwarnings("ignore")
reload(sys)
sys.setdefaultencoding("utf-8")

KEY_DOMAIN_NAME = 'domain_name'
KEY_REGISTRAR = 'registrar'
KEY_NAME = 'name'
KEY_ORG = 'org'
KEY_ZIPCODE = 'zipcode'
KEY_CREATION_DATE = 'creation_date'
KEY_EXPIRATION_DATE = 'expiration_date'
KEY_EMAILS = 'emails'
KEY_NAME_SERVERS = 'name_servers'
THRESHOLD_DISTANCE = 75
weights = [0,1,1,1,1,1,1,1]



def __levenshtein__(str1, str2):
    str1 = str1.encode('utf-8')
    str2 = str2.encode('utf-8')
    return Levenshtein.distance(str1.lower(),str2.lower())

def __dist_domain__name__(domain_name_a, domain_name_b):
    return __levenshtein__(str(domain_name_a).lower(), str(domain_name_b).lower())


def __dist_registrar__(registrar_a, registrar_b):
    registrar_a = registrar_a if not registrar_a is None else ''
    registrar_b = registrar_b if not registrar_b is None else ''
    registrar_a = registrar_a.encode('utf-8')
    registrar_b = registrar_b.encode('utf-8')
    return __levenshtein__(str(registrar_a).lower(), str(registrar_b).lower())


def __dist_name__(name_a, name_b):
    return __levenshtein__(str(name_a).lower(), str(name_b).lower())


def __dist_org_by_min_dist__(orgs_a=[], orgs_b=[]):
    orgs_seed = orgs_a.split(',') if not isinstance(orgs_a, list) else orgs_a
    orgs_file = orgs_b.split(',') if not isinstance(orgs_b, list) else orgs_b
    if not orgs_seed and not orgs_file:
        return float(0)
    elif not orgs_seed:
        orgs_seed = ['']
    elif not orgs_file:
        orgs_file = ['']

    dist_org = __levenshtein__(str(orgs_seed[0]), str(orgs_file[0]))
    for org_s in orgs_seed:
        org_s = org_s.encode('utf-8')
        for org_f in orgs_file:
            org_f = org_f.encode('utf-8')
            dist_org = min(str(dist_org), str(__levenshtein__(str(org_s), str(org_f))))
    return float(dist_org)


def __dist_zipcode_by_min_dist__(zipcodes_a=[], zipcodes_b=[]):
    zipcodes_seed = zipcodes_a.split(',') if not isinstance(zipcodes_a, list) else zipcodes_a
    zipcodes_file = zipcodes_b.split(',') if not isinstance(zipcodes_b, list) else zipcodes_b
    if not zipcodes_seed and not zipcodes_file:
        return float(0)
    elif not zipcodes_seed:
        zipcodes_seed = ['']
    elif not zipcodes_file:
        zipcodes_file = ['']
    dist_zipcode = __levenshtein__(str(zipcodes_seed[0]), str(zipcodes_file[0]))
    for zipcode_s in zipcodes_seed:
        for zipcode_f in zipcodes_file:
            dist_zipcode = min(str(dist_zipcode), str(__levenshtein__(str(zipcode_s), str(zipcode_f))))
    return float(dist_zipcode)


# ttl by proportion, more close tu cero, more close is the ttl
def get_diff_ttl(creation_date_a, creation_date_b,expiration_date_a, expiration_date_b):
    if not creation_date_a and not creation_date_b and not expiration_date_a and not expiration_date_a:
        return float(0)
    elif not creation_date_a and not creation_date_b and expiration_date_a and expiration_date_b:
        if expiration_date_a == expiration_date_a:
            return float(0)
        else:
            return float(1)
    elif creation_date_a and creation_date_b and not expiration_date_a and not expiration_date_b:
        if creation_date_a == creation_date_a:
            return float(0)
        else:
            return float(1)
    elif not creation_date_a or not creation_date_b or not expiration_date_a or not expiration_date_b:
        return float(1)
    else:
        cd_a = datetime.strptime(creation_date_a, '%d-%m-%Y') if not isinstance(creation_date_a, datetime) else creation_date_a
        ed_a = datetime.strptime(expiration_date_a, '%d-%m-%Y') if not isinstance(expiration_date_a, datetime) else expiration_date_a
        cd_b = datetime.strptime(creation_date_b, '%d-%m-%Y') if not isinstance(creation_date_b, datetime) else creation_date_b
        ed_b = datetime.strptime(expiration_date_b, '%d-%m-%Y') if not isinstance(expiration_date_b, datetime) else expiration_date_b
        ttl_days_b = float(abs(cd_b - ed_b).days)  # time to live
        ttl_days_a = float(abs(cd_a - ed_a).days)
        if ttl_days_b == ttl_days_a:
            return float(0)
        else:
            return float(1) - ((ttl_days_b / ttl_days_a) if ttl_days_b <= ttl_days_a else (ttl_days_a / ttl_days_b))


# Method computing distance where emails are measured with "taking the minimun distance techniques "
def get_diff_emails_by_min_dist(emails_a=[], emails_b=[]):
    emails_seed = emails_a.split(',') if not isinstance(emails_a, list) else emails_a
    emails_file = emails_b.split(',') if not isinstance(emails_b, list) else emails_b
    if not emails_seed and not emails_file:
        return float(0)
    elif not emails_seed:
        emails_seed = ['']
    elif not emails_file:
        emails_file = ['']

    dist_email = __levenshtein__(str(emails_seed[0]), str(emails_file[0]))
    for email_s in emails_seed:
        for email_f in emails_file:
            dist_email = min(str(dist_email), str(__levenshtein__(str(email_s), str(email_f))))
    return float(dist_email)


# Method computing distance where name_servers are measured with "taking the minimun distance techniques "
def get_diff_name_servers_by_min_dist(name_servers_a=[], name_servers_b=[]):
    if name_servers_a is None:
        name_servers_a = []
    if name_servers_b is None:
        name_servers_b = []
    name_servers_seed = name_servers_a.split(',') if not isinstance(name_servers_a, list) else name_servers_a
    name_servers_file = name_servers_b.split(',') if not isinstance(name_servers_b, list) else name_servers_b
    if not name_servers_seed and not name_servers_file:
        return float(0)
    elif not name_servers_seed:
        name_servers_seed = ['']
    elif not name_servers_file:
        name_servers_file = ['']

    dist_name_server = __levenshtein__(str(name_servers_seed[0]), str(name_servers_file[0]))
    for name_server_s in name_servers_seed:
        for name_server_f in name_servers_file:
            dist_name_server = min(str(dist_name_server), str(__levenshtein__(str(name_server_s), str(name_server_f))))
    return float(dist_name_server)


def features_domains_attr(domain_name_a, registrar_a, name_a, orgs_a, zipcodes_a, creation_date_a,
                          expiration_date_a, emails_str_a, name_servers_str_a,
                          domain_name_b, registrar_b, name_b, orgs_b, zipcodes_b, creation_date_b,
                          expiration_date_b, emails_str_b, name_servers_str_b, ):
    dist_domain_name = __dist_domain__name__(domain_name_a, domain_name_b)
    dist_registrar = __dist_registrar__(registrar_a, registrar_b)
    dist_name = __dist_name__(name_a, name_b)
    dist_org = round(__dist_org_by_min_dist__(orgs_a, orgs_b),2)
    dist_zipcode = round(__dist_zipcode_by_min_dist__(zipcodes_a, zipcodes_b),2)
    diff_ttl = round(get_diff_ttl(creation_date_a, creation_date_b,expiration_date_a, expiration_date_b),5)
    diff_emails = round(get_diff_emails_by_min_dist(emails_str_a, emails_str_b),2)
    diff_name_servers = round(get_diff_name_servers_by_min_dist(name_servers_str_a,name_servers_str_b),2)
    dict_result = dict(dist_domain_name=dist_domain_name,
                  dist_registrar=dist_registrar,
                  dist_name=dist_name,
                  dist_org=dist_org,
                  dist_zipcode=dist_zipcode,
                  dist_duration=diff_ttl,
                  dist_emails=diff_emails,
                  dist_name_servers=diff_name_servers)
    return dict_result, [dist_domain_name, dist_registrar, dist_name, dist_org, dist_zipcode,
                         diff_ttl, diff_emails, diff_name_servers]

def features_domains(whois_info_a={}, whois_info_b={}):
    # reload(sys)
    # sys.setdefaultencoding("utf-8")
    domain_name_a = whois_info_a.get(KEY_DOMAIN_NAME,'')
    registrar_a = whois_info_a.get(KEY_REGISTRAR,'')

    name_a = whois_info_a.get(KEY_NAME,'')
    orgs_a = whois_info_a.get(KEY_ORG,[])   # []
    zipcode_a = whois_info_a.get(KEY_ZIPCODE,[])  # []
    creation_date_a = whois_info_a.get(KEY_CREATION_DATE,None)
    expiration_date_a = whois_info_a.get(KEY_EXPIRATION_DATE,None)
    emails_a = whois_info_a.get(KEY_EMAILS, [])  # []
    name_servers_a = whois_info_a.get(KEY_NAME_SERVERS, [])  # []

    domain_name_b = whois_info_b.get(KEY_DOMAIN_NAME, '')
    registrar_b = whois_info_b.get(KEY_REGISTRAR, '')
    name_b = whois_info_b.get(KEY_NAME, '')
    orgs_b = whois_info_b.get(KEY_ORG, [])  # []
    zipcode_b = whois_info_b.get(KEY_ZIPCODE, [])  # []
    creation_date_b = whois_info_b.get(KEY_CREATION_DATE, '')
    expiration_date_b = whois_info_b.get(KEY_EXPIRATION_DATE, '')
    emails_b = whois_info_b.get(KEY_EMAILS, [])  # []
    name_servers_b = whois_info_b.get(KEY_NAME_SERVERS, [])  # []

    return features_domains_attr(domain_name_a, registrar_a, name_a, orgs_a, zipcode_a, creation_date_a,
                         expiration_date_a, emails_a,name_servers_a,
                         domain_name_b, registrar_b, name_b, orgs_b, zipcode_b, creation_date_b,
                         expiration_date_b, emails_b, name_servers_b)


def distance_domains(whois_info_a, whois_info_b):
    feature_values = features_domains(whois_info_a, whois_info_b)[1]
    multiply = list(np.multiply(feature_values, weights))
    sum_features = sum(multiply)
    return abs(sum_features)

def get_input_and_target_from(dmfs):
    inputs = []
    target = []
    for dmf in dmfs:
        inputs.append([1] + dmf.get_features().values())
        target.append(dmf.related)

    return inputs, target

def relate_domains(whois_info_a, whois_info_b):
    return distance_domains(whois_info_a, whois_info_b) <= THRESHOLD_DISTANCE


class WhoisObj(object):
    # passive total
    def __init__(self,domain, library='pw'):
        self.domain = domain
        self.raw_whois = None
        self.features_whois = None

        if library == 'pw':
            self.__process_features_pw__()
        elif library == 'pt':
            self.__process_features_pt__()
        else:
            raise ValueError("Incorrect Library, option are pw and pt")


    def features_measure_distance_dict(self,obj_b):
        feature_distance_dict, _ = features_domains(self.features_whois, obj_b.features_whois)
        return feature_distance_dict

    def feature_measure_distance_array(self,obj_b):
        _, feature_distance_array = features_domains(self.features_whois, obj_b.features_whois)
        return feature_distance_array

    def get_whois_distance(self,obj_b):
        return distance_domains(self.features_whois, obj_b.features_whois)

    def get_whois_relationship(self,obj_b):
        return relate_domains(self.features_whois, obj_b.features_whois)

    def domain_duration(self):
        if self.features_whois:
            creation_date_a = self.features_whois[KEY_CREATION_DATE]
            expiration_date_a = self.features_whois[KEY_EXPIRATION_DATE]
            if not creation_date_a or not expiration_date_a:
                return None
            cd_a = datetime.strptime(creation_date_a, '%d-%m-%Y') if not isinstance(creation_date_a, datetime) else creation_date_a
            ed_a = datetime.strptime(expiration_date_a, '%d-%m-%Y') if not isinstance(expiration_date_a, datetime) else expiration_date_a
            if cd_a and ed_a:
                return float(abs(cd_a - ed_a).days)
            else:
                return None

    def __process_features_pt__(self):
        if not self.raw_whois:
            self.__process_result_pt__()

        if not self.raw_whois:
            print("Process Feature PT not working ")

        result = self.raw_whois if self.raw_whois else {}

        def get_emails():
            emails = result.get('contactEmail', [])
            emails = [] if emails is None else emails
            emails = emails.split(',') if not isinstance(emails, list) else emails
            return emails

        def get_domain_name():
            domain = result.get('domain', '')
            domain = '' if domain is None else domain
            return domain

        def get_name_servers():
            ns = result.get('nameServers', [])
            ns = ns.split(',') if isinstance(ns, basestring) else ns
            return ns

        def get_registrar():
            registrar = result.get('registrar', '')
            registrar = '' if registrar is None else registrar
            return registrar

        def get_name():
            name_admin = result.get('admin', {}).get('name', '')
            name_tech = result.get('tech', {}).get('name', '')
            name_registrant = result.get('registrant', {}).get('name', '')
            names = list(set([name_admin, name_tech, name_registrant]))
            names = [n for n in names if n or not n == '']
            return names[0] if len(names) > 0 else ''

        def get_creation_date():
            cd_str = result.get('registered', None)
            if cd_str:
                if isinstance(cd_str, basestring):
                    try:
                        return dateutil.parser.parse(cd_str)
                    except:
                        print("Date Invalid ", self.id, cd_str)
                        return None
                elif isinstance(cd_str, datetime):
                    return cd_str
            else:
                return None

        def get_expiration_date():
            cd_str = result.get('expiresAt', None)
            if cd_str:
                if isinstance(cd_str, basestring):
                    try:
                        return dateutil.parser.parse(cd_str)
                    except:
                        print("Date Invalid ", self.id, cd_str)
                        return None
                elif isinstance(cd_str, datetime):
                    return cd_str
            else:
                return None

        def get_zipcodes():
            postalcode_admin = result.get('admin', {}).get('postalCode', '')
            postalcode_tech = result.get('tech', {}).get('postalCode', '')
            postalcode_registrant = result.get('registrant', {}).get('postalCode', '')
            return list(set([postalcode_admin, postalcode_tech, postalcode_registrant]))

        def get_orgs():
            org_admin = result.get('admin', {}).get('organization', '')
            org_tech = result.get('tech', {}).get('organization', '')
            org_registrant = result.get('registrant', {}).get('organization', '')
            return list(set([org_admin, org_tech, org_registrant]))

        features = dict(
            emails=get_emails(),
            domain_name=get_domain_name(),
            name_servers=get_name_servers(),
            registrar=get_registrar(),
            name=get_name(),
            creation_date=get_creation_date(),
            expiration_date=get_expiration_date(),
            zipcode=get_zipcodes(),
            org=get_orgs()
        )
        self.features_whois = features

    def __process_result_pw__(self):  # python whois lib
        d = self.__get_top_level_domain__()
        try:
            if d:
                r = pythonwhois.get_whois(d)
                self.raw_whois = r
            elif not d:
                print("PW, domain null " + str(self.domain) + " ")
        except WhoisException as e:
            print("PW rejects " + str(self.domain) + ", ERROR TRACE " + e.message)
        except:
            print("PW rejects " + str(self.domain))

    def __process_features_pw__(self):
        if not self.raw_whois:
            self.__process_result_pw__()

        if not self.raw_whois:
            print("Process Feature PW not working ")

        result = self.raw_whois if self.raw_whois else {}
        raw = result.get('raw', None)
        raw = raw[0].split('\n') if not raw is None else []
        raw = ','.join(raw).encode('utf-8').strip().split(',')
        # self.features_info_pw

        def get_dict(dict_obj, key, default):
            value = dict_obj.get(key, type(default))
            if not isinstance(value, type(default)) and not type(default) == None:
                return default
            else:
                return value

        def get_emails():
            emails = result.get('emails', [])
            emails = [] if emails is None else emails
            emails = emails.split(',') if not isinstance(emails, list) else emails
            return emails

        def get_domain_name():
            pattern = r'^.*Domain Name:.*$'
            indices = [i for i, x in enumerate(raw) if re.search(pattern, x)]
            fields = str(raw[indices[0]]).split(':') if len(indices) > 0 else []
            domain_name = fields[1].strip() if len(fields) > 0 else ''
            if not domain_name or domain_name == '':
                domain_name = self.__get_top_level_domain__()
                domain_name = domain_name if not domain_name else ''
            return domain_name

        def get_name_servers():
            ns = result.get('nameservers', [])
            ns = ns.split(',') if isinstance(ns, basestring) else ns
            return ns

        def get_registrar():
            registrar = result.get('registrar', '')
            if not registrar or registrar == '':
                pattern = r'^.*Registrar:.*$'
                indices = [i for i, x in enumerate(raw) if re.search(pattern, x)]
                fields = str(raw[indices[0]]).split(':') if len(indices) > 0 else []
                registrar = fields[1].strip() if len(fields) > 0 else ''
            return registrar[0] if isinstance(registrar, list) else registrar

        def get_name():
            contacts = get_dict(result, 'contacts', {})
            name_admin = get_dict(contacts, 'admin', {}).get('name', '')
            name_tech = get_dict(contacts, 'tech', {}).get('name', '')
            name_registrant = get_dict(contacts, 'registrant', {}).get('name', '')
            names = list(set([name_admin, name_tech, name_registrant]))
            names = [n for n in names if n or not n == '']
            name = names[0] if len(names) > 0 else ''
            if not name or name == '':
                pattern = r'^.*name:.*$'
                indices = [i for i, x in enumerate(raw) if re.search(pattern, x)]
                names = []
                for indice in indices:
                    fields = str(raw[indice]).split(':') if len(indices) > 0 else []
                    names.append(fields[1].strip() if len(fields) > 0 else '')
                return names[0] if len(names) > 0 else ''
            else:
                return name

        def get_creation_date():
            cd_str = result.get('creation_date', [])
            if cd_str and len(cd_str) > 0:
                if isinstance(cd_str[0], basestring):
                    try:
                        return dateutil.parser.parse(cd_str[0])
                    except:
                        print("Date Invalid ", self.id, cd_str[0])
                        return None
                elif isinstance(cd_str[0], datetime):
                    return cd_str[0]
            else:
                return None

        def get_expiration_date():
            ed_str = result.get('expiration_date', [])
            if ed_str and len(ed_str) > 0:
                if isinstance(ed_str[0], basestring):
                    try:
                        return dateutil.parser.parse(ed_str[0])
                    except:
                        print("Date Invalid ", self.id, ed_str[0])
                        return None
                elif isinstance(ed_str[0], datetime):
                    return ed_str[0]
            else:
                return None

        def get_zipcodes():
            contacts = get_dict(result, 'contacts', {})
            postalcode_admin = get_dict(contacts, 'admin', {}).get('postalcode', '')
            postalcode_tech = get_dict(contacts, 'tech', {}).get('postalcode', '')
            postalcode_registrant = get_dict(contacts, 'registrant', {}).get('postalcode', '')
            return list(set([postalcode_admin, postalcode_tech, postalcode_registrant]))

        def get_orgs():
            contacts = get_dict(result, 'contacts', {})
            org_admin = get_dict(contacts, 'admin', {}).get('organization', '')
            org_tech = get_dict(contacts, 'tech', {}).get('organization', '')
            org_registrant = get_dict(contacts, 'registrant', {}).get('organization', '')
            return list(set([org_admin, org_tech, org_registrant]))

        features = dict(
            emails= get_emails(),
            domain_name=get_domain_name(),
            name_servers=get_name_servers(),
            registrar=get_registrar(),
            name=get_name(),
            creation_date=get_creation_date(),
            expiration_date=get_expiration_date(),
            zipcode=get_zipcodes(),
            org=get_orgs()
        )
        self.features_whois = features

    def __get_top_level_domain__(self):
        try:
            if is_ip(self.domain) or not self.domain or self.domain == '':
                return None
            d = get_tld('http://www.'+self.domain)
            if d.find('www.') >= 0:
                return d.split('www.')[1]
            else:
                return d
        except:
            return None

    def __process_result_pt__(self): # passive total
        d = self.__get_top_level_domain__()
        try:
            if d:
                client = WhoisRequest.from_config()
                raw_results = client.get_whois_details(query=d)
                self.raw_whois = raw_results
            elif not d:
                print("PT, domain null " + str(d) + " " + str(self.id))
        except:
            print("PT rejects " + str(self.domain) + " ")


def compare_domains_ids(d1, d2, library='pw', raw=False):
    if not d1 or not d2:
        raise ValueError("Domains empty")
    obj_a = WhoisObj(d1, library)
    if library=='pw':
        time.sleep(5)
    obj_b = WhoisObj(d2, library)

    table = Texttable()
    table.set_cols_align(["c", "c", "c","c"])
    table.set_cols_valign(["t", "m", "m", "m"])
    table.set_cols_dtype(['t','a','a','f'])  # automatic
    data = [["Features", str(d1), str(d2), "Distance"]]
    features_measure_dist = obj_a.features_measure_distance_dict(obj_b)
    keys_set = set(obj_a.features_whois.keys())
    dates_set = set([KEY_EXPIRATION_DATE, KEY_CREATION_DATE])
    for key in list(keys_set - dates_set):
        data.append([key,obj_a.features_whois[key],obj_b.features_whois[key],features_measure_dist['dist_'+key]])
    data.append(['Domain Duration (in days)', obj_a.domain_duration(),obj_b.domain_duration(),features_measure_dist['dist_duration']])
    data.append(['Total Distance:', "","",obj_a.get_whois_distance(obj_b)])
    table.add_rows(data)
    print table.draw() + "\n"
    print("WHOIS Distance: " + str(obj_a.get_whois_distance(obj_b)))
    print("Are related?: " + str(obj_a.get_whois_relationship(obj_b)))
    
    if raw:
        print("Library for getting WHOIS: " + library)
        print("################# WHOIS INFO First Domain #######################")
        pp.pprint(obj_a.raw_whois)
        print("################ WHOIS INFRO Second Domain ########################")
        pp.pprint(obj_b.raw_whois)

if __name__ == '__main__':
    parser = argparse.ArgumentParser("This python scripts can calculate the WHOIS Similarity Distance between two given domains.")
    parser.add_argument("domain_a", help="give First domain to compare")
    parser.add_argument("domain_b", help="give Second domain to compare")
    parser.add_argument("-rw", "--rawwhois", help="See WHOIS information of both domains", action="store_true")
    parser.add_argument("-wl", "--whoislibrary",help="Set whois library to choose, pt => passivetotal, pw => pythonwhois", choices=['pw', 'pt'], default='pw')
    parser.add_argument("-th", "--distance_threshold",help="Set the threshold for determine if two domains are related "
                                                          +"using their WHOIS information", default='75', type=int)
    parser.add_argument("-v",'--version', action='version',
                        version='%(prog)s version: {version}'.format(version=__version__))
    args = parser.parse_args()
    THRESHOLD_DISTANCE = args.distance_threshold
    compare_domains_ids(args.domain_a, args.domain_b, args.whoislibrary,args.rawwhois)

