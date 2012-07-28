#!/usr/bin/env python2.6

#AppGettr v0.23 by espes
#March 2011
#GPL, I guess

#Code sucks (who needs comments?), deal with it.
__version__ = "0.23"

import os
import platform
from time import sleep
from itertools import *

def grouper(n, iterable, fillvalue=None):
    "grouper(3, 'ABCDEFG', 'x') --> ABC DEF Gxx"
    args = [iter(iterable)] * n
    return izip_longest(fillvalue=fillvalue, *args)

import json
import urllib
class ResourceNotFoundError(Exception):
  pass
class AppTrackrAPI(object):
  def __init__(self):
    self.apiUrl = "http://api.apptrackr.org/"
    self.publicKey = """
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCxyZS+9iSODM7uiv4g1CNV36xg
zHsEgZaFxcy88BibdUxAEFwr0CgCy1TrnTMe87PmAElCmatPpGUSYmFQtM7YEsPf
UNfB/8q/dEeHXAH2I93PGN3wdLicY9K2SOz6GbkAkoEnpGSYwOKIBBsKi4/wZ33W
UcFkpmqMMlaiSc0zjwIDAQAB
-----END PUBLIC KEY-----"""
  
  def makeRequest(self, request):
    #print request
    data = urllib.urlencode({'request': json.dumps({'request': json.dumps(request)})})
    #print data
    for i in xrange(10):
      try:
        f = urllib.urlopen(self.apiUrl, data)
        r = json.loads(f.read())
        f.close()
      except (IOError, ValueError):
        print "### Apptrackr api error. Retrying %d/10" % (i+1)
        continue
      else:
        if r['code'] == 402:
          print "### Apptrackr's annoyed at us. Taking a nap... (%d/10)" % (i+1)
          
          import progressbar
          pbar = progressbar.ProgressBar().start()
          for i in pbar(range(120)): #sleep for 2 minutes
            sleep(1)
          pbar.finish()
          
          continue
        else:
          break
    else:
      raise Exception, "Could not contact apptrackr api"
    
    if r['code'] != 200:
      if r['code'] == 410:
        raise ResourceNotFoundError
      raise Exception, "Error %d" % (r['code'],)
    #TODO: verify signature
    return json.loads(r['data'])
  
  def getLinksForAppId(self, appId):
    return self.makeRequest({
      'object': 'Link',
      'action': 'get',
      'args': {
        'app_id': appId
      }
    })['links']
  
  def getPriceForAppId(self, appId):
    return self.makeRequest({
      "object": "App",
      "action": "getDetails",
      "args": {
        "app_id": appId,
        "fields": ["price"]
      }
    })['app']['price']
  
  def getNameForAppId(self, appId):
    return self.makeRequest({
      "object": "App",
      "action": "getDetails",
      "args": {
        "app_id": appId,
        "fields": ["name"]
      }
    })['app']['name']
  
  def getVersionsForAppIds(self, appIds):
    ret = {}
    for subIds in grouper(50, appIds):
      ret.update(self.makeRequest({
        "object": "App",
        "action": "checkUpdates",
        "args": {
          "appids": [id for id in subIds if id is not None],
        }
      })['versions'])
    return ret
  
  def getAppIdsForBundles(self, bundles):
    ret = {}
    for subIds in grouper(50, bundles):
      ret.update(self.makeRequest({
        "object": "Bundle",
        "action": "getItunesIDs",
        "args": {
          "bundleList": [id for id in subIds if id is not None],
        }
      }))
    return ret

api = AppTrackrAPI()


#Reads OS X alias file path data
def aliasToPath(aliasData):
  from Carbon import File
  alias = File.Alias(rawdata=aliasData)
  fsref = alias.FSResolveAlias(None)[0]
  return fsref.as_pathname()


#Stuff for parsing iTunes Library files
#thanks to https://code.google.com/p/titl/
import struct
import zlib
def unpackFromFile(fmt, f):
  return struct.unpack(fmt, f.read(struct.calcsize(fmt)))

def itl_readHdfm(f, startPos):
  hl, fl, unkn = unpackFromFile(">III", f)
  l, = unpackFromFile("=B", f)
  version = f.read(l)

  f.seek(startPos+hl)

def itl_decrypt(f):
  from Crypto.Cipher import AES
  
  h = f.read(4)
  assert h == "hdfm"
  itl_readHdfm(f, 0)

  data = f.read()
  def decryptPortion(encrypted):
    if len(encrypted)%16:
      encrypted = encrypted[:-(len(encrypted)%16)]
    aes = AES.new("BHUILuilfghuila3", AES.MODE_ECB)
    decrypted = aes.decrypt(encrypted)+data[len(encrypted):]
    decompressed = zlib.decompress(decrypted)
    return decompressed

  try:
    r = decryptPortion(data[:102400])
  except zlib.error:
    r = decryptPortion(data)

  return r

def itl_parseFilePaths(f):
  while True:
    blockStartPos = f.tell()
    blockType = f.read(4)
    if blockType == "": break

    #print hex(blockStartPos)

    if blockType == "hohm":
      headerLength, recLength, hohmType = unpackFromFile(">III", f)
      #print "hohm", hohmType
      if hohmType == 1: #Path (Alias)
        assert platform.system() == "Darwin"
        unkn = f.read(8)

        pathData = f.read(recLength-(f.tell()-blockStartPos))
        path = aliasToPath(pathData)
        yield path
        #print "alias path", path
      elif hohmType == 0x0D: #Path (string)
        unkn = f.read(12)

        encodings = [
          "us-ascii",
          "utf-16be",
          "utf-8",
          "windows-1252"
        ]
        encoding = encodings[ord(unkn[11])]

        length, = unpackFromFile(">I", f)
        unkn = f.read(8)

        path = unicode(f.read(length), encoding)
        yield path
        #print "string path", path

      f.seek(blockStartPos+recLength)
    elif blockType == "hdsm":
      #print "hdsm"
      headerLength, = unpackFromFile(">I", f)
      f.seek(blockStartPos+headerLength)
    elif blockType == "hpim":
      #print "hpim"
      headerLength, = unpackFromFile(">I", f)
      f.seek(blockStartPos+headerLength)
    elif blockType == "hptm":
      #print "hptm"
      headerLength, = unpackFromFile(">I", f)
      f.seek(blockStartPos+headerLength)
    elif blockType == "htim":
      #print "htim"
      headerLength, = unpackFromFile(">I", f)
      f.seek(blockStartPos+headerLength)
    elif blockType == "haim":
      #print "haim"
      headerLength, = unpackFromFile(">I", f)
      f.seek(blockStartPos+headerLength)
    elif blockType == "hdfm":
      itl_readHdfm(f, blockStartPos)
    elif blockType in ("hghm", "halm", "hilm", "htlm", "hplm", "hiim"):
      #print blockType
      headerLength, = unpackFromFile(">I", f)
      f.seek(blockStartPos+headerLength)
    else:
      #raise Exception, "unknown block %r" % (blockType,)
      return

def extractLibraryFiles(libraryFile):
  decryptedFile = StringIO(itl_decrypt(open(libraryFile, "rb")))
  return list(itl_parseFilePaths(decryptedFile))


#Stuff for accessing iTunes preferencs
import plistlib
import biplist
import zipfile
import fnmatch
import re
from cStringIO import StringIO

def getAppleIdFromPref(prefData):
  #Search for email-like strings, it's easier than re'ing the format
  strings = re.findall(r".(?:\x00[a-zA-Z0-9._%+-@])+", prefData)
  for s in strings:
    s = s[1:1+ord(s[0])*2].replace("\x00", "")
    if re.match(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}", s, re.IGNORECASE):
      return s
  return None

def parseiTunesPrefs():
  appleId = None
  libraryDir = None
  
  macPath = os.path.expanduser('~/Library/Preferences/com.apple.iTunes.plist')
  winPath = os.path.expandvars("%APPDATA%/Apple Computer/iTunes/iTunesPrefs.xml")
  if os.path.exists(macPath):
    plist = biplist.readPlist(macPath)
    appleId = plist.get("Store Apple ID")
    if appleId is None and "pref:130:Preferences" in plist:
      prefData = plist["pref:130:Preferences"]
      if isinstance(prefData, plistlib.Data):
        appleId = getAppleIdFromPref(prefData.data)
      else:
        appleId = getAppleIdFromPref(prefData)
    
    if "alis:1:iTunes Library Location" in plist:
      from Carbon import File
      aliasData = plist["alis:1:iTunes Library Location"]
      if isinstance(aliasData, plistlib.Data):
        aliasData = aliasData.data
      libraryDir = aliasToPath(aliasData)
  elif os.path.exists(winPath):
    plist = plistlib.readPlist(winPath)
    try:
      libraryDir = os.path.dirname(unicode(
        plist["User Preferences"]["iTunes Library XML Location:1"].data,
        "utf-16"))
    except KeyError:
      pass
    
    try:
      prefData = plist["User Preferences"]["Preferences:130"].data
      appleId = getAppleIdFromPref(prefData)
    except KeyError:
      pass
  return appleId, libraryDir


def readZipPlist(zipf, name):
  try:
    metadataFile = zipf.open(name)
    return plistlib.readPlist(metadataFile)
  except Exception:
    metadataFile = StringIO(zipf.read(name))
    return biplist.readPlist(metadataFile)

class NoMetadataError(Exception):
  pass
class IPAInfo(object):
  def __init__(self, fileName, appleId=None, acceptMissingMetadata=False):
    self.fileName = fileName
    #appId, appName, appVersion
    ipaZip = zipfile.ZipFile(fileName)
    
    for n in ipaZip.namelist():
      if fnmatch.fnmatch(n.lower(), "payload/*.app/info.plist"):
        infoPlist = readZipPlist(ipaZip, n)
        self.appVersion = infoPlist['CFBundleVersion']
        self.bundleName = infoPlist['CFBundleIdentifier']
        break
    else:
      raise Exception, "Can't find app Info.plist in %s" % (fileName,)
    
    self.appId = None
    self.appName = os.path.basename(fileName)
    try:
      metadataPlist = readZipPlist(ipaZip, "iTunesMetadata.plist")
      self.appId = metadataPlist['itemId']
      self.appName = metadataPlist['itemName']
      
      self.hasMetadata = True
    except KeyError:
      if not acceptMissingMetadata:
        raise NoMetadataError
      else:
        self.hasMetadata = False
    
    if self.hasMetadata:
      try:
        self.purchased = \
          metadataPlist["com.apple.iTunesStore.downloadInfo"]["accountInfo"]["AppleID"].lower() \
            == appleId
      except KeyError:
        try:
          self.purchased = metadataPlist['appleId'].lower() == appleId
        except KeyError:
          self.purchased = False
    else:
      self.purchased = False
    
  def setKnownAppId(self, appId):
    assert self.appId is None
    self.appId = appId
    #try:
    #  self.appName = api.getNameForAppId(appId)
    #except Exception:
    #  pass




import glob
from time import sleep

def versionNewer(cur, new):
  cur = re.sub(r"[^\d\.]", "", cur)
  new = re.sub(r"[^\d\.]", "", new)
  curt = tuple(map(int, filter(None, cur.split("."))))
  newt = tuple(map(int, filter(None, new.split("."))))
  
  curt += (0,)*(len(newt)-len(curt))
  
  return newt > curt

class IPAUpdater(object):
  def __init__(self, appleId=None, libraryFile=None, appPath=None):
    self.sitePreference = [
      "fileape.com",
      "2shared.com",
      "sendspace.com",
      "4shared.com",
      "mediafire.com",
      "megaupload.com",
      "zshare.net",
      "filedude.com",
      "appscene.org",
    ]
    
    self.libraryFile = libraryFile
    
    self.paths = filter(os.path.exists, map(os.path.expanduser, [
      "~/Music/iTunes/Mobile Applications",
      "~/Music/iTunes/iTunes Music/Mobile Applications",
      "~/Music/iTunes/iTunes Media/Mobile Applications",
      "~/My Music/iTunes/Mobile Applications",
      "~/My Music/iTunes/iTunes Music/Mobile Applications",
      "~/My Music/iTunes/iTunes Media/Mobile Applications",]))
    
    #Append the app path if it hasn't already been seen
    if appPath and os.path.exists(appPath):
      for p in self.paths:
        if os.path.abspath(p) == os.path.abspath(appPath):
          break
      else:
        self.paths.append(appPath)
    
    self.appleId = appleId
  

  def siteRank(self, shorthand):
    if shorthand == "magnet": #can't handle torrent at all :/
      return 10000000000
    try:
      return self.sitePreference.index(shorthand.lower())
    except ValueError:
      print "fixme: unranked site %s" % (shorthand, )
      return len(self.sitePreference)

  def linkRank(self, l):
    if not l['active']:
      return (1000000000, -l['time'])
    return (self.siteRank(l['shorthand']), -l['time'])
  
  def run(self):
    ipaPaths = []
    for p in self.paths:
      print "Looking for apps in %s" % (p,)
      ipaPaths.extend(glob.glob(os.path.join(p, "*.ipa")))
    
    #load ipas from the iTunes library
    if self.libraryFile and os.path.exists(self.libraryFile):
      print "Reading iTunes library..."
      try:
        for p in extractLibraryFiles(self.libraryFile):
          if p.lower().endswith(".ipa"):
            ipaPaths.append(p)
      except Exception as ex:
        if isinstance(ex, ImportError):
          print " - Can't parse iTunes library, install pyCrypto kthx"
        else:
          print " - Can't parse iTunes library, something broke :("
      
    
    #remove duplicate ipa files
    for i, p in enumerate(ipaPaths):
      for p2 in ipaPaths[i+1:]:
        if p is None or p2 is None: continue
        if os.path.abspath(p) == os.path.abspath(p2):
          ipaPaths[i] = None
          break
    ipaPaths = [p for p in ipaPaths if p is not None]
    
    print "Parsing apps..."
    
    updateIpas = []
    for p in ipaPaths:
      try:
        ipa = IPAInfo(p, self.appleId, True)
      except Exception as e:
        print p, e
        continue
      if not ipa.purchased:
        updateIpas.append(ipa)
    
    findMetadataIpas = [ipa for ipa in updateIpas if not ipa.hasMetadata]
    bundlelookup = api.getAppIdsForBundles([ipa.bundleName for ipa in findMetadataIpas])
    print "Retrieving metadata for poorly cracked apps..."
    for ipa in findMetadataIpas:
      appid = bundlelookup[ipa.bundleName]
      if type(appid) is not int:
        print "Can't find metadata for %s!" % (ipa.fileName,)
        updateIpas.remove(ipa)
        continue
      ipa.setKnownAppId(appid)
      print " - ", ipa.appName
    
    print "Loaded %d apps" % (len(updateIpas),)
    
    print "Getting latest versions..."
    latestVersions = api.getVersionsForAppIds([ipa.appId for ipa in updateIpas])
    #print latestVersions
    
    justPrint = False
    
    if not justPrint:
      print "Queueing updates..."
      jdgetter = JDWebGetter()
      gettertested = False
      updateCount = 0
    
    for ipa in updateIpas:
      version = latestVersions[str(ipa.appId)]
      if isinstance(version, bool):
        print "%s not in AppTrackr, can't update!" % (ipa.appName,)
        continue
      if not versionNewer(ipa.appVersion, version): continue
      
      try:
        links = api.getLinksForAppId(ipa.appId)
      except ResourceNotFoundError:
        print "%s not in AppTrackr, can't update!" % (ipa.appName,)
        continue
      versions = sorted(links.keys(), cmp=versionNewer, reverse=True)
      #print versions
      linksGet = []
      for v in versions:
        if not versionNewer(ipa.appVersion, v): break
        linkOrder = sorted(links[v], key=self.linkRank)
        linksGet.extend(linkOrder)
      
      if len(linksGet) > 0:
        #print ipa.fileName
        #print ipa.appName, ipa.appId, ipa.appVersion
        #print versions[0], ">", ipa.appVersion
        urls = [link['url'] for link in linksGet]
        #print urls
        
        print "Queueing %d links for %s v%s (from %s)" % (
          len(urls),
          ipa.appName,
          versions[0],
          ipa.appVersion)
        
        if not justPrint:
          if not gettertested:
            while not jdgetter.testOnline():
              print "Please ensure JDownloader is running and the Web Interface enabled"
              print "Press Enter to retry"
              raw_input()
            gettertested = True
        
          jdgetter.queueAppLinks(ipa.appName, urls)
          updateCount += 1
        else:
          for bestlink in linksGet[:1]:
            print bestlink['cracker'], bestlink['url']
            print
    
    if not justPrint:
      print "Queued %d updates" % updateCount
      if updateCount > 0:
        jdgetter.startDownloads()
        sleep(5)
        print "Monitoring Downloads..."
        while jdgetter.checkDownloads():
          sleep(2)
        print "Should be done!"


#Queues and monitors downloads using the JDownloader Web Interface
from BeautifulSoup import BeautifulSoup
from binascii import crc32
class JDWebGetter(object):
  def __init__(self):
    self.ip = "127.0.0.1"
    self.port = 8765
    
    self.username = "JD"
    self.password = "JD"
    
    self.appQueues = []
    self.linkHashes = {}
  
  def baseUrl(self):
    return "http://%s:%s@%s:%d/" % (
      self.username,
      self.password,
      self.ip,
      self.port
    )
  
  def testOnline(self):
    try:
      return "JDownloader - WebInterface" in urllib.urlopen(self.baseUrl()).read()
    except IOError:
      return False
  
  def encodeLink(self, link, appName=""):
    crc = "%08x" % (crc32(link)&0xFFFFFFFF,)
    self.linkHashes[crc] = link
    
    return "%s_%s" % (appName.encode("utf-8"), crc)
  def decodeLink(self, enc):
    crc = enc.rpartition("_")[-1]
    return self.linkHashes[crc]
  def addLink(self, link, appName=""):
    before = urllib.urlopen(self.baseUrl()+"link_adder.tmpl").read()
    beforeSoup = BeautifulSoup(before)
    beforeTable = beforeSoup.find("table", {"class": "tabledownload"})
    assert len(beforeTable.findAllNext("tr")) == 1, "Something's already in the Linkadder! Help!"
    
    #add link
    urllib.urlopen(self.baseUrl()+"link_adder.tmpl", urllib.urlencode({
      'do': 'Add',
      'addlinks': link
    })).read()
    
    sleep(3)
    
    while "LinkGrabber still Running!" in urllib.urlopen(self.baseUrl()+"link_adder.tmpl").read():
      sleep(1)
    
    after = urllib.urlopen(self.baseUrl()+"link_adder.tmpl").read()
    afterSoup = BeautifulSoup(after)
    assert afterSoup.find("tr", {"class": "package"}) is not None
    
    #If the link's not available
    if afterSoup.find("tr", {"class": "downloadonline"}) is None:
      #remove it
      #print "offline", link
      urllib.urlopen(self.baseUrl()+"link_adder.tmpl", urllib.urlencode({
        'do': 'Submit',
        'checkallbox': 'on',
        'package_all_add': '0',
        'adder_package_name_0': 'idontthinkthismatters',
        'package_single_add': '0 0',
        'selected_dowhat_link_adder': 'remove'
      })).read()
      return False
    
    #Add it
    urllib.urlopen(self.baseUrl()+"index.tmpl", urllib.urlencode({
      'do': 'Submit',
      'checkallbox': 'on',
      'package_all_add': '0',
      'adder_package_name_0': self.encodeLink(link, appName),
      'package_single_add': '0 0',
      'selected_dowhat_link_adder': 'add'
    })).read()
    #print "added", link
    return True
  def removeLink(self, link):
    for dlink, filename, status, (packageSoup, downloadSoup) in self.getDownloads():
      if dlink == link:
        package_all_downloads = packageSoup.find("input", {"name": "package_all_downloads"})['value']
        package_single_download = downloadSoup.find("input", {"name": "package_single_download"})['value']
        
        urllib.urlopen(self.baseUrl()+"index.tmpl", urllib.urlencode({
          'do': 'submit',
          'package_all_downloads': package_all_downloads,
          'package_single_download': package_single_download,
          'selected_dowhat_index': 'remove'
        })).read()
        
        break
    else:
      assert False
  def startDownloads(self):
    urllib.urlopen(self.baseUrl()+"index.tmpl", urllib.urlencode({
      'do': 'start',
    })).read()
  def stopDownloads(self):
    urllib.urlopen(self.baseUrl()+"index.tmpl", urllib.urlencode({
      'do': 'stop',
    })).read()
  def getDownloads(self):
    downloadPage = urllib.urlopen(self.baseUrl()+"index.tmpl").read()
    downloadSoup = BeautifulSoup(downloadPage)
    for pstatus, dstatus in [
      ('packageactivated', 'downloadactivated'),
      ('packagedeactivated', 'downloaddeactivated'),
      ('packagerunning', 'downloadrunning'),
      ('packagefinished', 'downloadfinished')]:
      
      packages = downloadSoup.findAll("tr", {"class": pstatus})
      for p in packages:
        linkenc = p.find("a", {"name": "PackageInfo"}).contents[0]
        try:
          link = self.decodeLink(linkenc)
        except KeyError:
          continue
      
        download = p.findNextSiblings("tr", {"class": dstatus})[0]
        status = download.find("span", {"class": "ladestatus"}).contents[0]
        filename = download.find("a", {"name": "LinkInfo"}).contents[0]
        
        yield link, filename, status, (p, download)
  def isStatusFail(self, status):
    return "Plugin error" in status \
        or "Hoster problem" in status \
        or "Fatal error" in status \
        or "Aborted" in status \
        or "Unexpected" in status
  def checkDownloads(self):
    busy = False
    for link, filename, status, _ in self.getDownloads():
      #print status
      for appName, q in self.appQueues:
        if link in q:
          assert q.index(link) == 0
          if "100 %" in status or "100%" in status:
            print "finished %s:" % (appName,), link
            self.appQueues.remove((appName, q))
          elif self.isStatusFail(status) or (filename[-4] == "." and filename[-3:].lower() != "ipa"):
            #if (filename[-4] == "." and filename[-3:].lower != "ipa"):
            self.removeLink(link)
            print "link for %s broken:" % (appName,), link
            q.pop(0)
            while len(q) > 0:
              if self.addLink(q[0], appName):
                busy = True
                break
              print "link for %s offline:" % (appName,), q.pop(0)
            else:
              print "No working links for %s" % (appName)
              
          else:
            busy = True
    return busy
  def queueAppLinks(self, appName, links):
    for l in links:
      self.encodeLink(l, appName)
    
    found = False
    for link, filename, status, _ in self.getDownloads():
      if link in links:
        if "100 %" in status or "100%" in status:
          print " - already finished:", link
          return
        elif self.isStatusFail(status):
          print " - found broken:", link
          #print "found not running, remove", link
          links.remove(link)
        else:
          #elif "ETA" in status or "Wait" in status or "Captcha" in status:
          print " - found running:", link
          assert not found
          links.remove(link)
          links = [link]+links
          found = True
    
    
    #try to add them
    if not found:
      while len(links) > 0:
        if self.addLink(links[0], appName):
          break
        links.pop(0)
    
    #print "queue", links
    if len(links) > 0:
      self.appQueues.append( (appName, links) )


def main():
  print "AppGettr v%s by espes" % (__version__,)
  print
  
  appleId, libPath = parseiTunesPrefs()
  if appleId is None:
    appleId = raw_input("Please enter your apple id: ")
  else:
    print "Detected Apple ID as %s" % (appleId,)
  appleId = appleId.lower()
  
  libraryFile = None
  appPath = None
  
  if libPath:
    if platform.system() == "Darwin":
      libraryFile = os.path.join(libPath, "iTunes Library")
    else:
      libraryFile = os.path.join(libPath, "iTunes Library.itl")
    
    #If it doesn't exist, assume apps are in "Mobile Applications"
    if not os.path.exists(libraryFile):
      appPath = os.path.join(libPath, "Mobile Applications")
  
  if libraryFile is None or not os.path.exists(libraryFile):
    for p in map(os.path.expanduser, [
      "~/Music/iTunes/iTunes Library",
      "~\My Documents\My Music\iTunes\iTunes Library.itl",
      "~\Music\iTunes\iTunes Library.itl",
      "~\My Music\iTunes\iTunes Library.itl"]):
      if os.path.exists(p):
        libraryFile = p
        break
  
  if libraryFile:
    print "Found iTunes library file at %s" % (libraryFile,)
  
  print
  
  IPAUpdater(appleId, libraryFile=libraryFile, appPath=appPath).run()

if __name__ == "__main__":
  if platform.system() == "Windows":
    # Work around <http://bugs.python.org/issue6058>.
    import codecs
    codecs.register(lambda name: name == 'cp65001' and codecs.lookup('utf-8') or None)
    
    #Also, windows cmd fails
    import sys
    sys.stdout = codecs.getwriter(sys.stdout.encoding)(sys.stdout, "replace")
  
  try:
    main()
  except Exception as ex:
    import traceback
    print
    print "Oh noes! An error occured!"
    traceback.print_exc(ex)
  finally:
    print
    print "Press Enter to quit"
    raw_input()
  