import os
import sys
import sqlite3
import requests
from lxml import etree
import codecs
import datetime
import gzip

default_datadir = './data'
etag_database = default_datadir + '/etag.db'
feed_list_url = 'https://nvd.nist.gov/download.cfm'

def nvd_feeds(url):
    '''
    this function will break fairly easily if anything about the NVD website 
    changes. 

    All it does is try to find a url that matches a very specific pattern. If 
    the website changes those patterns then this will need to be changed as 
    well.

    This function could be made smarter to prevent this sort of hackery. For 
    instance you might prefer zip files instead of gz files. No way of changing
    that without changing script. 
    '''

    print('Querying {0} for NVD feeds'.format(url))

    pattern = ('https://nvd.nist.gov/feeds/xml/cve/', '.xml.gz')

    r = requests.get(url)
    if r.status_code == requests.codes.ok:
        for element in r.text.split():
            #find beginning of url
            s = element.find(pattern[0])
            e = element.find(pattern[1])

            #if pattern discoverd, check for end
            if s > -1 and e > -1:
                
                download_url = element[s:e+len(pattern[1])] 
                yield download_url

def download_feed(feed, filename, db):
    '''
    Download feed locally

    This tries to cache previous downloads. This is wholly untested and may 
    not act as expected as I have thrown it together quickly

    '''
    print('Checking NVD Feed {0}'.format(feed))
    r = requests.get(feed, stream=True)
    tag = r.headers['etag'].strip('"')

    dbcur = db.cursor()
    
    dbcur.execute('select etag from etags where etag = (?)', [(tag)])
    ret = dbcur.fetchone()
    cached = False if ret is None else True

    if r.status_code == 200 and not cached:
        print('    Downloading NVD Feed from {0} to {1}'.format(feed, filename))
        with open(filename, 'wb') as f:
            for chunk in r:
                f.write(chunk)

        dbcur.execute('insert into etags values (?)', [(tag)])
        db.commit()
    else:
        print('    This is *probably* cached at {0}'.format(filename)) 
        r.close()

def download(datadir, db, data_url):
    '''
    this will download all the nvd feed files 
    '''

    for feed in nvd_feeds(data_url):        
        filename = feed.split('/')[-1]
        filepath = os.path.join(datadir, filename)

        download_feed(feed, filepath, db)

def nvd_feeds_to_process(datadir):

    today = datetime.datetime.today()
    compressed_files = [os.path.join(datadir, f) for f in os.listdir(datadir) if f.endswith('.xml.gz')]

    for f in compressed_files:
        mtime = datetime.datetime.fromtimestamp(os.path.getmtime(f))
        modified_today = (today - mtime) < datetime.timedelta(days=1)

        if modified_today: 
            yield f

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
    sf = gzip.open(filename, 'rb')
    context = etree.iterparse(sf, events=events)
    
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

def run(datadir=default_datadir ,dbfile=etag_database, data_url=feed_list_url):

    # setup data directory
    if not os.path.exists(datadir):
        os.mkdir(datadir)

    # setup database
    conn = sqlite3.connect(dbfile)
    cur = conn.cursor()
    cur.execute('create table if not exists etags (etag text)')

    download(datadir, conn, data_url)
    files = nvd_feeds_to_process(datadir) 

    for f in files: 
        make_csv(f, f.rstrip('.gz') + '.csv')

    conn.commit()
    conn.close()

if __name__ == '__main__':
    
    run()
