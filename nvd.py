import os
import sys
import requests
from lxml import etree
import codecs

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

    def csv(self):
        r = '{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},"'.format(
            self.number,
            self.published,
            self.lastmodified,
            self.cvss_score,
            self.cvss_access_vector,
            self.cvss_access_complexity,
            self.cvss_authentication,
            self.cvss_confidentiality_impact,
            self.cvss_integrity_impact,
            self.cvss_availability_impact,
            self.cvss_source,
            self.cvss_generated
        )

        return r + self.summary + '"'

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

def make_csv(source_xml_file, target_csv_file):
    print('Generating csv file: ' + target_csv_file)
    target = codecs.open(target_csv_file, 'w', 'utf-8')
    target.write('CVENumber,PublishedDateTime,LastModifiedDateTime,CVSSScore,CVSSAccessVector,CVSSAccessComplexity,CVSSAuthentication,CVSSConfidentialityImpact,CVSSIntegrityImpact,CVSSAvailabilityImpact,CVSSSource,CVSSGeneratedDateTime,CVESummary\r\n')
    for entry in iterate_nvd_feed(source_xml_file):
        target.write(entry.csv() + '\r\n')

def run():

    download()
    files = nvd_feeds_to_process()

    for f in files:
        make_csv(f, f + '.csv')

if __name__ == '__main__':
    
    run()
