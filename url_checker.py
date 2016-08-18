# -*- coding: utf-8 -*-
import urllib2
import os
import argparse
import re
import threading
import subprocess
import datetime

###############################
# Safe Browser statics
###############################
appVersion = "0.4"

try:
    keyFile = open('url_checker.key', 'r')
    safe_browser_key = keyFile.readline().strip().split(' ')[1]
    safe_browser_URL = keyFile.readline().strip().split(' ')[1]
except Exception as e:
    print "[I] Unable to find the Payload.key file and load the " \
        "SafeBrowser key."
    print "[I] Will not check SafeBrowser Status"
    safe_browser_key = None
    safe_browser_URL = None


# This thread class will handle each URL
class url_Thread(threading.Thread):
    # Create the thread
    def __init__(self, threadID, url, args):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.quiet = args.quiet
        self.URL = url
        self.timeOut = args.timeOut

    # Run with some error checking
    def run(self):
        self.data = testPayloadURL(self.URL, self.quiet, self.timeOut)


def safeBrowserTest(key, url):
    response = urllib2.urlopen(safe_browser_URL.format(key=key,
        appversion=appVersion, url=url)).read()
    return response


def isEmpty(s):
    return not bool(s and s.strip())


def testPayloadURL(url, quiet, timeOut):
    try:
        if not quiet:
            print "[I] Testing the single URL %s" % url
        response = urllib2.urlopen(url, None, timeOut)
        if response.geturl() == url:
            result = "[M] The identified URL %s is active" % url
            if safe_browser_key is not None:
                safe_browser_response = safeBrowserTest(safe_browser_key, url)
                if isEmpty(safe_browser_response):
                    safe_browser_response = "safe; Please submit for evaluation"
                result += "; Google thinks the URL is: " + safe_browser_response
            result += "; IP address is: %s" % pingable(url)
        else:
            result = "[S] The URL %s is believed safe; it redirects to %s" \
                % (url, response.geturl())

    except Exception as e:
        result = "[E] The URL %s is not reacheable: %s" % (url, e)

    return result


def pingable(url):
    url = url.split('/')
    target = url[2]
    try:
        ping = subprocess.check_output("ping -c 2 " + target, shell=True)
        ip = re.search('([\d]*\.[\d]*\.[\d]*\.[\d]*)', ping)
        ip = ip.group()

    except:
        ip = "NO IP"

    return ip


def cleanURL(url):
    if bool(re.match('h..p', url, re.I)):
        url = "http" + url[4:]
    elif bool(re.match('meow', url, re.I)):
        url = "http" + url[4:]
    else:
        url = "http://" + url

    url = re.sub('\[\.\]', '.', url)
    return url.strip('\n')


def singleURL(args):
    result = []
    target_url = cleanURL(args.target)
    result.append(testPayloadURL(target_url, args.quiet, args.timeOut))
    return result


def fileURL(args):
    result = []
    threadList = []
    i = 1

    # If messages are requested, provide them
    if not args.quiet:
        print "[i] Using %s file as a source for URLS" % args.target

    # Search through the provided file and start the testing
    with file(args.target) as f:

        for target_URL in f:
            print target_URL
            t = url_Thread(i, cleanURL(target_URL), args)
            threadList.append(t)
            i += 1

        for thread in threadList:
            thread.start()

        for thread in threadList:
            thread.join()

        for thread in threadList:
            result.append(thread.data)

    return result


def writeIt(finished_out, outfile):
    try:
        if not finished_out:
            print "[-] No data to write"
            return
        # keeping as troubleshooting option
        if not outfile:
            for row in finished_out:
                print row
        else:
            print "[+] Writing output to %s" % outfile
            try:
                # auto close the file when finished
                with open(outfile, 'wb') as t_file:
                    for row in finished_out:
                        t_file.write(row + "\n")
            except IOError, err:
                print "[-] Error writing output file: %s" % str(err)
                return
    except UnicodeEncodeError, err:
        print "[-] Error writing output: %s" % str(err)
        return


def main():
    # Play nice and handle arguments
    parser = argparse.ArgumentParser(prog="payload_checker.py",
        version=appVersion, description="A tool to check URLs.  The tool " +
        "checks if the URL is active and checks the Google Safe Browsing" +
        " status.")

    # additional options
    parser.add_argument("-q", help="Hide the status messages [stdout]",
        action="store_true", dest="quiet", default=False)
    parser.add_argument("-w", help="Write out put to file", action="store",
        dest="outfile", default=datetime.datetime.now().
        strftime("%Y-%m-%d %H:%M:%S"))
    parser.add_argument("-t", help="The amount of time in seconds that the" +
        " tester will wait for a connection to succeed; default 30", type=int,
        action="store", dest="timeOut", default=30)
    parser.add_argument('target', metavar='targetURL or filename', nargs=1,
        action="store", help="targetURL A URL to check; filename A text" +
        " file of URLS, one per line, that will be checked.  URLs should be" +
        "\"live\".")

    args = parser.parse_args()
    #make whichever first positional argument the target of the test
    args.target = args.target[0]

    if not os.path.isfile(args.target):
        writeIt(singleURL(args), None)
    else:
        mal_results = []
        saf_results = []
        err_results = []
        results = fileURL(args)
        for row in results:
            if re.match('\[M\]', row, re.I):
                mal_results.append(row)
            if re.match('\[S\]', row, re.I):
                saf_results.append(row)
            if re.match('\[E\]', row, re.I):
                err_results.append(row)
        print "Thank you for using payload_checker %s" % appVersion
        writeIt(mal_results, 'MAL' + str(args.outfile))
        writeIt(saf_results, 'SAF' + str(args.outfile))
        writeIt(err_results, 'ERR' + str(args.outfile))


if __name__ == "__main__":
    main()