import os
import sys
import requests

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

def download(datadir = default_datadir, all_files = False):

    if not os.path.exists(datadir):
        os.mkdir(datadir)

    for feed in nvd_feeds():
        this_file = False
        filename = feed.split('/')[-1]
        filepath = os.path.join(datadir, filename)

        '''
        the "modified" and "recent" files contain all the latest additions and updates
        "recent" is a subset of "modified" that does not include updates to older CVE data as far as I can tell right now
        '''
        if filename.find('modified') > -1 or filename.find('recent') > -1:
            this_file = True

        if not os.path.exists(filepath):
            this_file = True

        if all_files or this_file:
            download_feed(feed, filepath)

def run():

    download()

if __name__ == '__main__':
    
    run()
