#!/usr/bin/env python
#-*- coding: utf-8 -*-

import argparse
import pprint as pp
import time
import warnings

from texttable import Texttable
from whois_similarity_distance.util.whois_obj import WhoisObj
from .__version__ import __version__
from .util.constants import KEY_EXPIRATION_DATE, KEY_CREATION_DATE, KEY_DOMAIN_NAME

warnings.filterwarnings("ignore")


def compare_domains_ids(d1, d2, library='pw', raw=False):
    if not d1 or not d2:
        raise ValueError("Domains empty")
    obj_a = WhoisObj(d1, library)
    if library == 'pw':
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
    domain_name_set =set([KEY_DOMAIN_NAME])
    for key in list(keys_set - dates_set - domain_name_set):
        data.append([key,obj_a.features_whois[key],obj_b.features_whois[key],features_measure_dist['dist_'+key]])
    data.append(['Domain Duration (in days)',
                 obj_a.domain_duration(),
                 obj_b.domain_duration(),
                 features_measure_dist['dist_duration']])
    data.append([KEY_DOMAIN_NAME + '*',
                 obj_a.features_whois[KEY_DOMAIN_NAME],
                 obj_b.features_whois[KEY_DOMAIN_NAME],
                 features_measure_dist['dist_domain_name']])
    data.append(['Total Distance:', "","",obj_a.get_whois_distance(obj_b)])
    table.add_rows(data)
    print(table.draw() + "\n")
    print("* Domain Name distance is excluded of total sum")
    print("WHOIS Distance: " + str(obj_a.get_whois_distance(obj_b)))
    print("Are related?: " + str(obj_a.get_whois_relationship(obj_b)))

    if raw:
        print("Library for getting WHOIS: " + library)
        print("################# WHOIS INFO First Domain #######################")
        pp.pprint(obj_a.raw_whois)
        print("################ WHOIS INFRO Second Domain ########################")
        pp.pprint(obj_b.raw_whois)


def main():
    parser = argparse.ArgumentParser("This python scripts can calculate the WHOIS Similarity "
                                     "Distance between two given domains.")
    parser.add_argument("domain_a", help="give First domain to compare")
    parser.add_argument("domain_b", help="give Second domain to compare")
    parser.add_argument("-rw", "--rawwhois", help="See WHOIS information of both domains", action="store_true")
    parser.add_argument("-wl", "--whoislibrary",help="Set whois library to choose, pt => passivetotal, "
                                                     "pw => pythonwhois", choices=['pw', 'pt'], default='pw')
    parser.add_argument("-th", "--distance_threshold",help="Set the threshold for determine if two domains are related "
                                                          +"using their WHOIS information", default='75', type=int)
    parser.add_argument("-v",'--version', action='version',
                        version='%(prog)s version: {version}'.format(version=__version__))
    args = parser.parse_args()
    global THRESHOLD_DISTANCE
    THRESHOLD_DISTANCE = args.distance_threshold
    compare_domains_ids(args.domain_a, args.domain_b, args.whoislibrary,args.rawwhois)


if __name__ == '__main__':
    main()
