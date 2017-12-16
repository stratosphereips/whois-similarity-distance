#-*- coding: utf-8 -*-
# Copyright (C) 2016-2017 Stratosphere Lab
# This file is part of ManaTI Project - https://stratosphereips.org
# See the file 'LICENSE' for copying permission.
# Created by Raul B. Netto <raulbeni@gmail.com> on 12/3/17.
import os
import sys
import warnings
import dateutil
import Levenshtein
import numpy as np

from datetime import datetime
from passivetotal.libs.whois import *
from six.moves import reload_module
from .util.constants import KEY_DOMAIN_NAME, KEY_REGISTRAR, KEY_NAME, KEY_ORG, KEY_ZIPCODE, \
    KEY_CREATION_DATE, KEY_EXPIRATION_DATE, KEY_EMAILS, KEY_NAME_SERVERS, weights

warnings.filterwarnings("ignore")
reload_module(sys)

# TO-DO this is not working python > 3.
#  The bug of encode(utf-8) is still present for python > 3
if sys.version_info <= (3,0):
    reload(sys)
    sys.setdefaultencoding('utf-8')

os.environ["PYTHONIOENCODING"] = "utf-8"


def __levenshtein__(str1, str2):
    str1 = str1.encode('utf-8')
    str2 = str2.encode('utf-8')
    return Levenshtein.distance(str1.lower(),str2.lower())

def __dist_domain__name__(domain_name_a, domain_name_b):
    return __levenshtein__(str(domain_name_a).lower(), str(domain_name_b).lower())


def __dist_registrar__(registrar_a, registrar_b):
    registrar_a = registrar_a if not registrar_a is None else ''
    registrar_b = registrar_b if not registrar_b is None else ''
    registrar_a = registrar_a.encode('utf-8') if not isinstance(registrar_a, list) else registrar_a[0].encode('utf-8')
    registrar_b = registrar_b.encode('utf-8') if not isinstance(registrar_b, list) else registrar_b[0].encode('utf-8')
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


def __get_date_aux__(date):
    try:
        return datetime.strptime(date, '%d-%m-%Y') \
            if not isinstance(date, datetime) else date
    except Exception as ex:
        return dateutil.parser.parse(date)


# ttl by proportion, more close tu cero, more close is the ttl
def __get_diff_ttl__(creation_date_a, creation_date_b, expiration_date_a, expiration_date_b):

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
        cd_a = __get_date_aux__(creation_date_a)
        ed_a = __get_date_aux__(expiration_date_a)
        cd_b = __get_date_aux__(creation_date_b)
        ed_b = __get_date_aux__(expiration_date_b)
        ttl_days_b = float(abs(cd_b - ed_b).days)  # time to live
        ttl_days_a = float(abs(cd_a - ed_a).days)
        if ttl_days_b == ttl_days_a:
            return float(0)
        else:
            return float(1) - ((ttl_days_b / ttl_days_a) if ttl_days_b <= ttl_days_a else (ttl_days_a / ttl_days_b))


# Method computing distance where emails are measured with "taking the minimun distance techniques "
def __get_diff_emails_by_min_dist__(emails_a=[], emails_b=[]):
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
def __get_diff_name_servers_by_min_dist__(name_servers_a=[], name_servers_b=[]):
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


def __features_domains_attr__(domain_name_a, registrar_a, name_a, orgs_a, zipcodes_a, creation_date_a,
                              expiration_date_a, emails_str_a, name_servers_str_a,
                              domain_name_b, registrar_b, name_b, orgs_b, zipcodes_b, creation_date_b,
                              expiration_date_b, emails_str_b, name_servers_str_b, ):
    dist_domain_name = __dist_domain__name__(domain_name_a, domain_name_b)
    dist_registrar = __dist_registrar__(registrar_a, registrar_b)
    dist_name = __dist_name__(name_a, name_b)
    dist_org = round(__dist_org_by_min_dist__(orgs_a, orgs_b),2)
    dist_zipcode = round(__dist_zipcode_by_min_dist__(zipcodes_a, zipcodes_b),2)
    diff_ttl = round(__get_diff_ttl__(creation_date_a, creation_date_b, expiration_date_a, expiration_date_b), 2)
    diff_emails = round(__get_diff_emails_by_min_dist__(emails_str_a, emails_str_b), 2)
    diff_name_servers = round(__get_diff_name_servers_by_min_dist__(name_servers_str_a, name_servers_str_b), 2)
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

    return __features_domains_attr__(domain_name_a, registrar_a, name_a, orgs_a, zipcode_a, creation_date_a,
                                     expiration_date_a, emails_a, name_servers_a,
                                     domain_name_b, registrar_b, name_b, orgs_b, zipcode_b, creation_date_b,
                                     expiration_date_b, emails_b, name_servers_b)


def distance_domains(whois_info_a, whois_info_b):
    feature_values = features_domains(whois_info_a, whois_info_b)[1]
    multiply = list(np.multiply(feature_values, weights))
    sum_features = sum(multiply)
    return abs(sum_features)