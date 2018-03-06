# Copyright (C) 2016-2017 Stratosphere Lab
# This file is part of ManaTI Project - https://stratosphereips.org
# See the file 'LICENSE' for copying permission.
# Created by Raul B. Netto <raulbeni@gmail.com> on 12/3/17.
import re
from datetime import datetime

import dateutil.parser
import pythonwhois
import numpy as np
import pickle
import os
import sys

from passivetotal.common.utilities import is_ip
from passivetotal.libs.whois import WhoisRequest
from pythonwhois.shared import WhoisException
from tld import get_tld
from six import string_types
from whois_similarity_distance.whois_distance import distance_domains, features_domains
from whois_similarity_distance.util.constants import THRESHOLD_DISTANCE, KEY_CREATION_DATE, KEY_EXPIRATION_DATE


# from passivetotal.libs.whois import *

def relate_domains(whois_info_a, whois_info_b):
    features_dist = features_domains(whois_info_a, whois_info_b)[0]
    feature_values = [features_dist["dist_registrar"],
                      features_dist["dist_name"],
                      features_dist["dist_zipcode"],
                      features_dist["dist_name_servers"],
                      features_dist["dist_domain_name"],
                      features_dist["dist_emails"],
                      features_dist["dist_duration"],
                      features_dist["dist_org"]]
    values_array = np.array([feature_values], np.int32)
    path = os.path.dirname(__file__)
    pickle_cls_path = os.path.join(path, 'gbc_cls.p')
    # GradientBoostingClassifier
    if sys.version_info <= (3, 0):
        gbc_cls = pickle.load(open(pickle_cls_path, "rb"))
    else:
        gbc_cls = pickle.load(open(pickle_cls_path, "rb"), encoding='latin1')

    y_pre = gbc_cls.predict(values_array)
    return y_pre[0] == 1


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
            ns = ns.split(',') if isinstance(ns, string_types) else ns
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
                if isinstance(cd_str, string_types):
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
                if isinstance(cd_str, string_types):
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
        raw = ','.join(raw).strip().split(',')
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
            ns = ns.split(',') if isinstance(ns, string_types) else ns
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
                if isinstance(cd_str[0], string_types):
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
                if isinstance(ed_str[0], string_types):
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