import os
import sys
import requests
import json
from lxml import etree
from collections import namedtuple

default_datadir = './data'

def nvd_feeds(url = 'http://nvd.nist.gov/download.cfm'):
    start = 'https://nvd.nist.gov/static/feeds/xml/cve/'
    end = '.xml'
    r = requests.get(url)
    if r.status_code == requests.codes.ok:
        for element in r.text.split():
            s = element.find(start)
            if s > -1:
                e = element.find(end)
                yield element[s:e+len(end)]

def download_feed(f, filename):
    '''
    Download feed locally
    '''
    msg = 'Downloading NVD Feed from {0} to {1}'
    print(msg.format(f, filename))
    r = requests.get(f)
    with open(filename, 'wb') as feed:
        feed.write(r.content)

def addendum_file(filename):
    '''
    the "modified" and "recent" files contain all the latest additions and updates
    "recent" is a subset of "modified" that does not include updates to older CVE data as far as I can tell right now
    '''

    if filename.find('modified') > -1 or filename.find('recent') > -1:
        return True
    else:
        return False


def download(datadir = default_datadir, all_files = False):

    if not os.path.exists(datadir):
        os.mkdir(datadir)

    for feed in nvd_feeds():        
        filename = feed.split('/')[-1]
        filepath = os.path.join(datadir, filename)
        this_file = addendum_file(filename)

        if not os.path.exists(filepath):
            this_file = True

        if all_files or this_file:
            download_feed(feed, filepath)

def nvd_feeds_to_process(datadir = default_datadir):
    '''
    return list of files to process
    if a file named init_load is present only return modified_feed
    if init_load not present then return all files that are not modfied or recent
    '''
    feed_files = []
    modified_feed = 'nvdcve-2.0-modified.xml'
    init_load = 'init_load'

    if os.path.exists(os.path.join(datadir, init_load)):
        feed_files.append(os.path.join(datadir, modified_feed))
    else:
        for root, dirs, files in os.walk(datadir):
            if datadir == root:
                for f in files:
                    if f.endswith('.xml') and not addendum_file(f):
                        feed_files.append(os.path.join(datadir, f))
                break

    return feed_files


class CVE(object):
    '''
    Example XML structure of entry
    <entry id="CVE-2010-4818">
        <vuln:cve-id>CVE-2010-4818</vuln:cve-id>
        <vuln:published-datetime>2012-09-05T19:55:01.443-04:00</vuln:published-datetime>
        <vuln:last-modified-datetime>2012-09-06T09:40:56.863-04:00</vuln:last-modified-datetime>
        <vuln:cvss>
          <cvss:base_metrics>
            <cvss:score>8.5</cvss:score>
            <cvss:access-vector>NETWORK</cvss:access-vector>
            <cvss:access-complexity>MEDIUM</cvss:access-complexity>
            <cvss:authentication>SINGLE_INSTANCE</cvss:authentication>
            <cvss:confidentiality-impact>COMPLETE</cvss:confidentiality-impact>
            <cvss:integrity-impact>COMPLETE</cvss:integrity-impact>
            <cvss:availability-impact>COMPLETE</cvss:availability-impact>
            <cvss:source>http://nvd.nist.gov</cvss:source>
            <cvss:generated-on-datetime>2012-09-06T09:37:00.000-04:00</cvss:generated-on-datetime>
          </cvss:base_metrics>
        </vuln:cvss>
        <vuln:cwe id="CWE-20" />
        <vuln:summary>The GLX extension in X.Org xserver 1.7.7 allows remote authenticated users to cause a denial of service (server crash) and possibly execute arbitrary code via (1) a crafted request that triggers a client swap in glx/glxcmdsswap.c; or (2) a crafted length or (3) a negative value in the screen field in a request to glx/glxcmds.c.</vuln:summary>
      </entry>
    '''

    published = None
    lastmodified = None
    cvss_score = None
    cvss_access_vector = None
    cvss_access_complexity = None
    cvss_authentication = None
    cvss_confidentiality_impact = None
    cvss_integrity_impact = None
    cvss_availability_impact = None
    cvss_source = None
    cvss_generated = None
    summary = None

    def __init__(self, cve):
        self.number = cve

    def __repr__(self):
        reprstr = 'ID: {0} CVSS SCORE: {1} - {2}'
        return reprstr.format(self.number, self.cvss_score, self.summary)

    def state(self):
        #return md5 sum of state
        pass

def iterate_nvd_feed(filename):

    events = ('end', 'start-ns', 'end-ns')
    context = etree.iterparse(filename, events=events)
    
    for event, element in context:
        if event == 'end':
            if element.tag.endswith('entry'):
                entry = CVE(element.get('id'))
                
                for item in element.iterchildren():

                    if item.tag.endswith('published-datetime'):
                        entry.published = item.text
                    elif item.tag.endswith('last-modified-datetime'):
                        entry.lastmodified = item.text

                    elif item.tag.endswith('cvss'):

                        for cvss_container in item.iterchildren():
                            for cvss_item in cvss_container.iterchildren():

                                if cvss_item.tag.endswith('score'):
                                    entry.cvss_score = cvss_item.text
                                
                                elif cvss_item.tag.endswith('access-vector'):
                                    entry.cvss_access_vector = cvss_item.text
                                
                                elif cvss_item.tag.endswith('access-complexity'):
                                    entry.cvss_access_complexity = cvss_item.text

                                elif cvss_item.tag.endswith('authentication'):
                                    entry.cvss_authentication = cvss_item.text

                                elif cvss_item.tag.endswith('confidentiality-impact'):
                                    entry.cvss_confidentiality_impact = cvss_item.text

                                elif cvss_item.tag.endswith('integrity-impact'):
                                    entry.cvss_integrity_impact = cvss_item.text

                                elif cvss_item.tag.endswith('availability-impact'):
                                    entry.cvss_availability_impact = cvss_item.text

                                elif cvss_item.tag.endswith('source'):
                                    entry.cvss_source = cvss_item.text

                                elif cvss_item.tag.endswith('generated-on-datetime'):
                                    entry.cvss_generated = cvss_item.text

                    elif item.tag.endswith('summary'):
                        entry.summary = item.text


                #yield the cve entry
                yield entry

                #clear memory of element and clean up parents
                element.clear()
                while element.getprevious() is not None:
                    del element.getparent()[0]

def run():

    #download()
    files = nvd_feeds_to_process()
    for f in files:

        for entry in iterate_nvd_feed(f):
            print(entry)


if __name__ == '__main__':
    
    run()
