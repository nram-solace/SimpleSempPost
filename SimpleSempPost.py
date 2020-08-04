#!/usr/bin/python
#--------------------------------------------------------------------------------
# SimpleSempPost.py
# 
# Solace SEMP XML HTTP POST
# Open HTTP connection to Solace broker and post list of SEMP requests
# time the processing for each
#
# Compatibility:
#  Python 3.6 - Works
#  Python 2.7 - Broken
#  Open and Post use urllib
#  Open2 and Post2 use urllib2
#
# TODO
#  Compression (Accept-Encoding: gzip)
#  Neither urllib nor urllib2 seem to support it.
#  See https://bugs.python.org/issue9500
#
# Ramesh Natarajan, Solace PSG
# Jul 31, 2020
#--------------------------------------------------------------------------------
import argparse, getpass, sys, logging, inspect, string, base64, time, pprint, gzip
#import httplib
import httplib2, urllib
import xml.etree.ElementTree as ET

me = "SimpleSempPost.py"

sample_semp_requests = [
"<rpc semp-version='soltr/9_5'><show><version/></show></rpc>",
"<rpc semp-version='soltr/9_5'><show><message-spool><detail/></message-spool></show></rpc>",
"<rpc semp-version='soltr/9_5'><show><message-vpn><vpn-name>*</vpn-name></message-vpn></show></rpc>"
];

#--------------------------------------------------------------------------------
# SimpleSEMP Class
#--------------------------------------------------------------------------------
class SimpleSEMP:
    'Simple SEMP POST'

    #-----------------------------------------------------------------------------
    # init class vars
    #
    def __init__ (self, prog, logger, host, user, passwd, url='/SEMP'):
        self.m_prog = prog
        self.m_logger = logger
        self.m_host = host 
        self.m_user = user
        self.m_passwd = passwd
        self.m_url = url
        self.m_hosturl = "{}{}".format(host,url)
        self.m_req = None
        self.m_resp = None
        self.m_xml = None
        self.m_xml_more = None
        self.m_statsfile = "./stats.out"
        self.m_logger.debug("SimpleSEMP initialzed")
        self.m_hdrs = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}
        self.Open2()

    #-------------------------------------------------------------------------------
    # open HTTP connection
    #
    def Open(self):
        auth = string.strip(base64.encodestring(self.m_user+":"+self.m_passwd))
        self.m_hdrs = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}
        self.m_hdrs["Authorization"] = "Basic %s" % auth
        self.m_logger.info("HTTP connection to :%s", self.m_host)
        self.m_logger.debug("Headers: %s", self.m_hdrs.items())
        try:
            self.m_conn = httplib.HTTPConnection(self.m_host)
        except httplib.InvalidURL as e:
            self.m_logger.exception(e)
            raise
        except:
            self.m_logger.exception("Unexpected exception %s", sys.exc_info()[0])
            raise
        return self.m_conn

    def Open2(self):
        log = self.m_logger  
        self.m_http = httplib2.Http()
        self.m_http.add_credentials(self.m_user, self.m_passwd)
        log.debug ("Opening to URL: %s", format(self.m_hosturl))
        log.debug("User: %s, Pass: %s", self.m_user, self.m_passwd)
        log.debug("headers: %s", self.m_hdrs)
        return


    #-------------------------------------------------------
    # Post a SEMP Reqquest and return response and elapsed time
    #
    def Post(self, req):
        self.m_logger.debug ("Posting request \"%s\" to url %s", req, self.m_url)
        p_hdrs = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}

        # Post request, get response and calcuate elapsed time
        t0 = time.time()
        self.m_conn.request("POST", self.m_url, req, self.m_hdrs)
        self.m_res = self.m_conn.getresponse()
        t1 = time.time()
        #-- end
        self.m_xml = self.m_xml_more = None

        if not self.m_res:
            raise Exception ("No SEMP response")
        self.m_resp = self.m_res.read()
        if self.m_resp is None:
            raise Exception ("Null SEMP response")
            return None
        return self.m_resp, t1 - t0

    def Post2(self, req):
        log = self.m_logger  
        log.debug("POSTing request: %s", req)
        t0 = time.time()
        rhdr, self.m_resp = self.m_http.request(self.m_hosturl, 
            "POST", 
            headers=self.m_hdrs,
            body=req )
        t1 = time.time()

        log.debug("response : %s", self.m_resp)
        log.debug("content  : %s",self.m_resp)
        return self.m_resp, t1 - t0
 
    #--------------------------------------------------------------------------------------------
    # Read list of XML SEMP requests (one per line) and return a list
    #
    def Read(self, fname):
        log = self.m_logger
        log.info ("Reading file %s", fname)
        return [line.rstrip('\n') for line in open(fname)]

    #--------------------------------------------------------------------------------------------
    # Save to file
    #
    def Save (self, fname, data=None):
        log = self.m_logger
        log.info ("Writing data to file %s", fname)
        if data is None:
            data = self.m_resp
        log.debug("data: \"%s\"", data)
        try:
            f = open (fname, "w")
            #print >>f, data
            print(data, file=f)
            f.close()
        except IOError as ex:
            log.exception (ex)
            raise ex
        except:
            log.exception ('Unexpected exception', sys.exc_info()[0])
            raise
   #--------------------------------------------------------------------------------------------
   # Look for more-cookie and return content
   # This is to support paged SEMP response
   #         
    def More(self, data = None):
        pp = pprint.PrettyPrinter(indent = 4)
        log = self.m_logger

        if data is None:
            data = self.m_resp
        #print ("data = {}". format(data))
        self.m_xml_more = None
        root = ET.fromstring(data)
        more=root.find("./more-cookie/rpc")
        if more is not None:
            self.m_xml_more = ET.tostring(more)
            log.debug("more-cookie: %s", self.m_xml_more)
        else:
            log.info("No more-cookie")
        return self.m_xml_more

    #-----------------------------------------------------------------------
    # Write stats info to stats file
    # 
    def WriteStats(self, data):
        log = self.m_logger
        try:
            f = open (self.m_statsfile, "a")
            #print >>f, data
            print (data, file=f)
            f.close()
            log.info("Updating stats file: %s with %s", self.m_statsfile, data)
        except IOError as ex:
            log.exception (ex)
            raise ex
        except:
            log.exception ('Unexpected exception', sys.exc_info()[0])
            raise

#--------------------------------------------------------------------------------------------
# initialize logging
#
def SetupLogging(prog, verbose):
    if (verbose > 0):
        logging.basicConfig(format='%(asctime)s : <%(name)s> [%(levelname)s] %(message)s', level=logging.DEBUG)
    else:
        logging.basicConfig(format='%(asctime)s : <%(name)s> [%(levelname)s] %(message)s', level=logging.INFO)
    return logging.getLogger(prog)

#--------------------------------------------------------------------------------------------
# main
#--------------------------------------------------------------------------------------------

def main(argv):

    # setup arguments

    p = argparse.ArgumentParser( prog=me,
    description='simple semp post', formatter_class=argparse.RawDescriptionHelpFormatter)


    p.add_argument('--user', dest="user", default="admin")
    p.add_argument('--password', dest='passwd', default='admin') 
    p.add_argument('--host', dest='host', default='localhost:8080')
    p.add_argument('--reqfile', dest='reqfile', required=False)
    p.add_argument('--outdir', dest='outdir', default='.')
    p.add_argument('--tag', dest='tag', default='test')
    p.add_argument('-v','--verbose', action="count", default=0)

    r = p.parse_args()

    log = SetupLogging(me, r.verbose)

    log.info("%s: starting", me)
    #log.debug('this is debug')
    #log.info("this is info")
    #log.warning('this is warning')
    #log.critical("this is critical")


    semp =  SimpleSEMP(me, log, r.host, r.user, r.passwd)
    semp_requests = sample_semp_requests
    if (r.reqfile):
        semp_requests = semp.Read(r.reqfile)
        log.debug("SEMP Reqests Read: %s", semp_requests)
    i = 0
    total_time = 0
    npost = 0
    t0 = time.time()
    for req in semp_requests:
        i = i+1
        m = 0
        log.info("Sending SEMP request-%d: %s", i, req)
        resp, td = semp.Post2(req)
        npost = npost + 1
        total_time = total_time + td
        log.info("Got Response in %f seconds", td)
        fname = "{}/response-{}.{}.xml".format(r.outdir,i,m)
        semp.Save(fname)
        while (semp.More() is not None):
            m = m+1
            resp, td = semp.Post2(semp.More())
            npost = npost + 1
            log.info("Got more Response (%d) in %f seconds", m, td)
            semp.Save("{}/response-{}.{}.xml".format(r.outdir,i,m))
    t1 = time.time()
    
    log.info ("Total POSTs        : %s", npost)
    log.info ("Time spent in POST : %s seconds", total_time)
    log.info ("Elapsed time       : %s", t1 - t0)
    semp.WriteStats("{}: {}: {}: {}: {}".format(r.tag, r.reqfile, npost, total_time, t1 - t0))

if __name__ == "__main__":
       main(sys.argv[1:])
