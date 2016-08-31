# -*- coding: utf-8 -*-
import tornado.web
import tornado.httpserver
import tornado.httpclient
import tornado.ioloop
import tornado.escape
import tornado.options
import session,logger,time
import asyncmongo,pymongo.objectid
import hashlib
from tornado.options import define, options
from xml.dom.minidom import getDOMImplementation,parseString

define("port", default=8888, help="DLNA Server", type=int)

settings = dict(
    cookie_secret="43oETzKXQAGaYdkL5gEmGeJJFuYh7EQnp2XdTP1o/Vo=",
    #---memcache settings---#
    session_cache='localhost:11211',
    session_expire = 1200,
    #---mongodb settings---#
    db_host = '127.0.0.1',
    db_port = 27017,
    db_name = 'DLNADB',
    db_maxcache = 10,
    db_maxconnections = 10
)
#Set up the session expire in seconds
session_expir = settings["session_expire"]
#XML implementor
impl = getDOMImplementation()
#Temporary host device MD5
host_device_md5 = ''

def CreateXMLTag(dom, tagname, value, type='text'):
    tag = dom.createElement(tagname)
    if value.find(']]>') > -1:
        type = 'text'
    if type == 'text':
        value = value.replace('&', '&amp;')
        value = value.replace('<', '&lt;')
        text = dom.createTextNode(value)
    elif type == 'cdata':
        text = dom.createCDATASection(value)
    tag.appendChild(text)
    return tag

def MD5Sum(text=""):
    m = hashlib.md5()
    m.update(text.encode('utf-8'))
    return m.hexdigest()

#Decoration for each API in order to validate the session at server side.
def CheckSession(func):
    def checksession(*args):
        request=args[0]
        session=application.session_manager.get(request)
	if not 'uid' in session.keys() or (int(time.time())-int(session['lastvisit'])) > session_expir:
            dom = impl.createDocument(None, 'result', None)
            top_element = dom.documentElement
            itemAuth = CreateXMLTag(dom,'auth','1')
            top_element.appendChild(itemAuth)
            request.set_header('Content-Type','text/xml')
            request.write(dom.toxml("utf-8"))
#            raise tornado.web.HTTPError(403)
        else:
            session['lastvisit']=time.time()
            application.session_manager.set(request,session)
            return func(*args)
    return checksession

def ErrorHandler(RequestHandler,func,e):
    #Write error log
    sError = "%s - %s" % (func,e)
    application.log_manager.log(3,sError)

    #Write error info to client
    dom = impl.createDocument(None, 'error', None)
    top_element = dom.documentElement
    err_code = CreateXMLTag(dom,'code','500')
    err_desc = CreateXMLTag(dom,'desc',sError)
    top_element.appendChild(err_code)
    top_element.appendChild(err_desc)
    RequestHandler.set_header('Content-Type','text/xml')
    RequestHandler.write(dom.toxml("utf-8"))


class BaseHandler(tornado.web.RequestHandler):
    minWaitTime = 15
    maxWaitTime = 900
    @property
    def db(self):
        if not hasattr(self,'_db'):
            self._db = asyncmongo.Client(pool_id='DLNA-DB',host=settings['db_host'],port=settings['db_port'],
                       maxcached=settings['db_maxcache'],maxconnections=settings['db_maxconnections'],dbname=settings['db_name'])
        return self._db

    @tornado.web.asynchronous
    def get(self):
        ErrorHandler(self,'LoginHandler.get()','Invalid request')
        self.finish()
    def post(self):
        pass
    def doProcess(self,callback):
        #sResult = None
        #callback(sResult)
        pass
    def onWaiting(self,sResult,error=None):
        if error:
            self.onResponse(sResult,error)
        if (sResult is not None):
            self.onResponse(sResult)
        else:
            iNextPollingTime = time.time() + self.minWaitTime
            if self.minWaitTime < self.maxWaitTime:
                self.minWaitTime *= 2
                tornado.ioloop.IOLoop.instance().add_timeout(
                iNextPollingTime,
                lambda: self.doProcess(callback=self.onWaiting)
            )
            else:
                self.onResponse(self.StopCode,'Server Time Out')
    def onResponse(self,sResult,error=None):
        pass
#Process user login, a parameter 'session_id' is necessary when client is trying to active a session.
class LoginHandler(BaseHandler):
    @tornado.web.asynchronous
    def post(self):
        if self.get_argument("uid") and self.get_argument("pwd") and self.get_argument("dvc"):
            self.doProcess(callback=self.onWaiting)
        else:
            ErrorHandler(self,'LoginHandler.post()','Invalid arguments')
            self.finish()
    def doProcess(self,callback):
        http=tornado.httpclient.AsyncHTTPClient()
        #Request HuanNet for authentication
        http.fetch("http://www.baidu.com",callback=callback)

    def onResponse(self,response,error=None):
        if response.error:
            ErrorHandler(self,'Begin LoginHandler.onResponse()',response.error)
            self.finish()
        else:
            try:
                result = tornado.escape.utf8(response.body)
                result = tornado.escape.xhtml_escape(result)        
                uid=self.get_argument("uid")
                pwd=self.get_argument("pwd")
                dvc=self.get_argument("dvc")
                #Demo users
                demoUsers = {"jazhang":"123456","zhangxh":"123456","vivi":"123456","flank":"123456","John":"123456"} 

                dom = impl.createDocument(None, 'result', None)
                top_element = dom.documentElement
                if pwd == demoUsers[uid]:
                    session = application.session_manager.get(self)
                    session['lastvisit']=time.time()
                    session['uid']=uid
                    session['dvc']=dvc
                    session['lastvisit']=time.time()
                    application.session_manager.set(self,session)
        
                    itemAuth =  CreateXMLTag(dom,'auth','0')
                    itemSID = CreateXMLTag(dom,'sid',session.session_id)
                    strLog = "User %s logged in at %s" % (uid,time.time())
                    application.log_manager.log(6,strLog)
                else:
                    itemAuth = CreateXMLTag(dom,'auth','1')
                    itemSID = CreateXMLTag(dom,'sid','')
                top_element.appendChild(itemAuth)
                top_element.appendChild(itemSID)
                self.set_header('Content-Type','text/xml')
                self.write(dom.toxml("utf-8"))
            except Exception,e:
                ErrorHandler(self,'End LoginHandler.onResponse()',e)
            finally:
                self.finish()
class CompareDeviceMD5(BaseHandler):
    uid = ''
    dvc = ''
    auth = 0
    hostDeviceMD5 = ''
    compareHostDevice = 0
    @CheckSession
    @tornado.web.asynchronous
    def post(self):
        try:
            session = application.session_manager.get(self)
            self.uid = session['uid']
            self.dvc = session['dvc']
            self.hostDeviceMD5 = self.get_argument('hostDeviceMD5')
            self.db.Devices.find({'uid':self.uid,'dvc':self.dvc},limit=1,callback=self.compareHostDeviceMD5)
        except Exception,e:
            ErrorHandler(self,'CompareDeviceMD5.post()',e)
            self.finish()
    def compareHostDeviceMD5(self,response,error):
        if error:
            ErrorHandler(self,'Begin CompareDeviceMD5.compareHostDeviceMD5',error)
            self.finish()
        try:
            session = application.session_manager.get(self)
            if len(response) > 0:
                if response[0]['md5'] != self.hostDeviceMD5:
                    self.compareHostDevice = 1
                    #update the host device md5 in DB after uploading descrepency in SYNC is called succeffully 
                    session['host_device_md5'] = self.hostDeviceMD5
                    application.session_manager.set(self,session)
                else:
                    response = [] 
            elif len(response) == 0:    #the user doesn't have the device record in DB
                self.compareHostDevice = 1
                session['host_device_md5'] = self.hostDeviceMD5
                application.session_manager.set(self,session)
            self.onHostDeviceMD5Updated(response,error)
        except Exception,e:
            ErrorHandler(self,'End CompareDeviceMD5.compareHostDeviceMD5()',e)
            self.finish()
    def onHostDeviceMD5Updated(self,response,error):
        if error:
            ErrorHandler(self,'Begin CompareDeviceMD5.onHostDeviceMD5Updated',error)
            self.finish()
        try:   
            #query guest devices' md5 against the user
            self.db.Devices.find({'uid':self.uid},callback=self.onResponse)
        except Exception,e:
            ErrorHandler(self,'End CompareDeviceMD5.onHostDeviceMD5Updated',e)
            self.finish()
    def onResponse(self,response,error):
        if error:
            ErrorHandler(self,'Begin CompareDeviceMD5.onResponse',error)
            self.finish()
        try:   
            strDevices=""
            if len(response) > 0:
                for item in response:
                    strDevices += "<Device><id>%s</id><md5>%s</md5></Device>" % (item['dvc'],item['md5'])
            strData = '<data>' + strDevices + '</data>'
            dom = impl.createDocument(None, 'result', None)
            top_element = dom.documentElement
        
            itemAuth = CreateXMLTag(dom,'auth',str(self.auth))
            itemStatus = CreateXMLTag(dom,'MD5Diff',str(self.compareHostDevice))
            dataDom = parseString(strData)
            itemData = dataDom.documentElement
    
            top_element.appendChild(itemAuth)
            top_element.appendChild(itemStatus)
            top_element.appendChild(itemData)
        
            self.write(dom.toxml("utf-8"))
        except Exception,e:
            ErrorHandler(self,'End CopareDeviceMD5.onResponse',e)
        finally:
            self.finish()
            
class CompareContentsMD5(BaseHandler):
    hostContentsMD5 = []
    uid = ''
    dvc = ''
    auth = 0
    host_contents_result = []
    guest_devices = []
    @CheckSession
    @tornado.web.asynchronous
    def post(self):
        try:
            session = application.session_manager.get(self)
            self.uid = session['uid']
            self.dvc = session['dvc']
            self.hostContentsMD5 = eval(self.get_argument('hostContentsMD5'))
            if len(self.hostContentsMD5) > 0:
                IDs = []
                for item in self.hostContentsMD5:
                    IDs.append(item.keys()[0])
                self.db.Contents.find({'$and':[{'dvc':self.dvc},{'uid':self.uid},{'id':{'$in':IDs}}]},['id','md5'],callback=self.onQueryHostContentsMD5)
            else:
                #Skip retrieving host device's contents if host device's contents MD5 poseted is empty
                self.onQueryHostContentsMD5Done(None,None)
            
        except Exception,e:
            ErrorHandler(self,'CompareContentMD5.post',e)
            self.finish()
    def onQueryHostContentsMD5(self,response,error):
        if error:
            ErrorHandler(self,'Begin CompareContentsMD5.onQueryHostContentsMD5',error)
            self.finish()
        try:
            #Compare host device contents' md5 against DB
            for item in self.hostContentsMD5:
                key = item.keys()[0]
                new_item = 1
                for item2 in response:
                    if item2['id'] == key:
                        new_item = 0
                        if item2['md5'] != item[key] and (key in self.host_contents_result)==False:
                            self.host_contents_result.append(key)
                if new_item == 1 and (key in self.host_contents_result)==False:
                    self.host_contents_result.append(key)
            #Remove contents in DB those are not in host device posted
            self.db.Contents.update({'$and':[{'dvc':self.dvc},{'uid':self.uid},{'id':{'$nin':self.hostContentsMD5}}]},{"$set":{"del":'1'}},callback=self.onQueryHostContentsMD5Done)

        except Exception,e:
            ErrorHandler(self,'End CompareContentsMD5.onQueryHostContentsMD5',e)
            self.finish()

    def onQueryHostContentsMD5Done(self,response,error):
        #Retrieve guest devices' contents MD5 list
        if error:
            ErrorHandler(self,'Begin CompareContentsMD5.onQueryHostContentsMD5Done',error)
            self.finish()
        try:
            self.guest_devices = eval(self.get_argument('devices'))
            if len(self.guest_devices) > 0:
                self.db.Contents.find({'$and':[{'uid':self.uid},{'dvc':{'$in':self.guest_devices}}]},['dvc','id','md5'],callback=self.onResponse)
            else:
                self.onResponse(None,None)
        except Exception,e:
            ErrorHandler(self,'End CompareContentsMD5.onQueryHostContentsMD5Done',e)
            self.finish()
    def onResponse(self,response,error):
        if error:
            ErrorHandler(self,'Begin CompareContentsMD5.onResponse',error)
            self.finish()
        try: 
            strDevices=""
            if response != None and  len(response) > 0:
                for item in response:
                    strDevices += "<content><deviceID>%s</deviceID><contentID>%s</contentID><md5>%s</md5></content>" % (item['dvc'],item['id'],item['md5'])
            strHostContents=''
            for cid in self.host_contents_result:
                strHostContents += "%s," % cid
            strData = '<contents>' + strDevices + '</contents>'
            dom = impl.createDocument(None, 'result', None)
            top_element = dom.documentElement
        
            itemAuth = CreateXMLTag(dom,'auth',str(self.auth))
            itemStatus = CreateXMLTag(dom,'hostContents',strHostContents)
            dataDom = parseString(strData)
            itemData = dataDom.documentElement
    
            top_element.appendChild(itemAuth)
            top_element.appendChild(itemStatus)
            top_element.appendChild(itemData)
            self.write(dom.toxml("utf-8"))
        except Exception,e:
            ErrorHandler(self,'End CompareContentsMD5.onResponse',e)
        finally:
            self.finish()
            

class SYNC(BaseHandler):
    lstcd = []
    lstGuestCD = []
    uid = ''
    dvc = ''
    auth = 0
    status = 1
    strCheckSum = ""
    strGuestCDResult = ""
    @CheckSession
    @tornado.web.asynchronous
    def post(self):
        try:
            session = application.session_manager.get(self)
            self.uid = session['uid']
            self.dvc = session['dvc']
            self.auth = 0 #valid session
            self.doUpdate(callback=self.onisexisted)
        except Exception,e:
            ErrorHandler(self,'SYNC.post()',e)
            self.finish()
    #Update CD container/item data
    def doUpdate(self,callback):
        strHostCD = ""
        try:
            session = application.session_manager.get(self)
            self.uid = session['uid']
            self.dvc = session['dvc']
            strHostCD = self.get_argument('hostCD').encode('utf-8')
            #ErrorHandler(self,'Debug',str(self.request.body))
            if len(self.lstcd) == 0 : self.lstcd = eval(strHostCD)
            if len(self.lstGuestCD) == 0 : self.listGuestCD = eval(self.get_argument('guestCD'))
            if len(self.lstcd) > 0: #always process the first item in the list
                item = self.lstcd[0]
                self.strCheckSum += item['md5'] #append md5 code for genertating the device's check sum code.
                self.db.Contents.find({'_id':'%s%s%s' % (self.uid,self.dvc,item['id'])},limit=1,callback=callback)
            else:
                #process getting guest devices CD if the host device's CD posted is empty
                self.status = 0
                self.getGuestCD(callback=self.onGuestCDDone)
        except Exception,e:
            ErrorHandler(self,'SYNC.doUpdate()',"%s \n %s" % (e,self.request.body))
            self.finish()
    def onisexisted(self,response,error):
        #print str(response)
        if error:
            ErrorHandler(self,'SYNC.onisexisted()',e)
            self.finish()
        try:   
            item = self.lstcd[0]
            item['del'] = 0
            item['uid'] = self.uid
            item['dvc'] = self.dvc
            #if item['desc'] == '':item['del'] = 1

            if len(response) > 0:
                self.db.Contents.update({'_id':'%s%s%s' % (self.uid,self.dvc,item['id'])},item,callback=self.onUpdated)
            else:
                item['_id'] = '%s%s%s' % (self.uid,self.dvc,item['id'])
                self.db.Contents.insert(item,callback=self.onUpdated)
        except Exception,e:
            ErrorHandler(self,'SYNC.onisexisted()',e)
            self.finish()
    def onUpdated(self,response,error):
        if error or response[0].get('ok') != 1:
            ErrorHandler(self,'SYNC.onUpdated()','Update item error:%s' % str(error))
            self.finish()
        #print 'item: %s\n' % str(response)
        try:
            del self.lstcd[0] #remove the first item in the list once it's saved to DB
            if len(self.lstcd) > 0:
                self.doUpdate(callback=self.onisexisted)
            else:
                self.status = 0 #all records updated
                #Get guest devices' contents against posted CD list
                self.getGuestCD(callback=self.onGuestCDDone)
        except Exception,e:
            ErrorHandler(self,'SYNC.onUpdated()',e)
            self.finish()
    def getGuestCD(self,callback):
        try:
            if len(self.listGuestCD) > 0:
                item = self.listGuestCD[0]
                self.db.Contents.find({'$and':[{'dvc':item['dvc']},{'uid':self.uid},{'id':{'$in':item['cd']}}]},callback=callback)
            else:
                self.doUpdateMD5(callback=self.onexistedMD5)
        except Exception,e:
            ErrorHandler(self,'SYNC.getGuestCD')
            self.finish()
    def onGuestCDDone(self,response,error):
        if error:
            ErrorHandler(self,'Begin SYNC.onGuestCDDone',error)
            self.finish()
        try:
            for item in response:
                self.strGuestCDResult += "<content><device>%s</device><id>%s</id><pid>%s</pid><desc>%s</desc><md5>%s</md5></content>" % (item['dvc'],item['id'],item['pid'],item['desc'],item['md5'])

            del self.listGuestCD[0]
            if len(self.listGuestCD) > 0:
                self.getGuestCD(callback=self.onGuestCDDone)
            else:
                self.doUpdateMD5(callback=self.onexistedMD5)
        except Exception,e:
            ErrorHandler(self,'End SYNC.onGuestCDDone',e)
            self.finish()


    def doUpdateMD5(self,callback):
        try:
            self.db.Devices.find({'uid':self.uid,'dvc':self.dvc},limit=1,callback=callback)
        except Exception,e:
            ErrorHandler(self,'SYNC.doUpdateMD5()',e)
            self.finish()
    def onexistedMD5(self,response,error):
        if error:
            ErrorHandler(self,'Begin SYNC.onexistedMD5()',error)
            self.finish()
        try:
            session = application.session_manager.get(self)
            if ('host_device_md5' in session.keys())==False:
                self.onResponse(None,None)
            else:
                #Update the host device's MD5 in DB
                if len(response) > 0:
                    self.db.Devices.update({'uid':self.uid,'dvc':self.dvc},{"$set":{"md5":session['host_device_md5']}},callback=self.onResponse)
                else:
                #Insert the new device along with the device's MD5 to DB
                    item = {}
                    item['uid'] = self.uid
                    item['dvc'] = self.dvc
                    item['md5'] = session['host_device_md5']
                    self.db.Devices.insert(item,callback=self.onResponse)
        except Exception,e:
            ErrorHandler(self,'End SYNC.onexistedMD5()',e)
            self.finish()
    def onResponse(self,response,error):
        if error:
            ErrorHandler(self,'Begin SYNC.onResponse()',error)
            self.finish()
        try:
            #session = application.session_manager.get(self)
            dom = impl.createDocument(None, 'result', None)
            top_element = dom.documentElement
        
            itemAuth = CreateXMLTag(dom,'auth',str(self.auth))
            itemStatus = CreateXMLTag(dom,'status',str(self.status))
            #itemHostMD5 = CreateXMLTag(dom,'hostDeviceMD5',session['host_device_md5'])
            strDataBegin = "<contents xmlns='urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/' xmlns:dc='http://purl.org/dc/elements/1.1/' xmlns:upnp='urn:schemas-upnp-org:metadata-1-0/upnp/'>"
            strDataEnd = "</contents>"
            strData = strDataBegin + self.strGuestCDResult + strDataEnd
            dataDom = parseString(strData)
            data = dataDom.documentElement
            top_element.appendChild(itemAuth)
            top_element.appendChild(itemStatus)
            #top_element.appendChild(itemHostMD5)
            top_element.appendChild(data)

            self.write(dom.toxml("utf-8"))
        except Exception,e:
            ErrorHandler(self,'End SYNC.onResponse()',e)
        finally:
            self.finish()

class PostMessage(BaseHandler):
    @CheckSession
    @tornado.web.asynchronous
    def post(self):
        try:
            session = application.session_manager.get(self)
            uid = session['uid']
            dvc = session['dvc']
            tuid = self.get_argument('tuid')
            tdvc = self.get_argument('tdvc')
            message = self.get_argument('msg')
            
            _from = "%s@%s" % (uid,dvc)
            _to = "%s@%s" % (tuid,tdvc)
            
            msg = {}
            msg['from'] = _from
            msg['to'] = _to
            msg['msg'] = message
            msg['dt'] = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
            msg['status'] = 1
            self.db.Messages.insert(msg,callback=self.onResponse)
        except Exception,e:
            ErrorHandler(self,'PostMessage.post()',e)
            self.finish()
    def onResponse(self,response,error):
        if error or response[0].get('ok') != 1:
            ErrorHandler(self,'PostMessage.onResponse()','Post message error:%s' % str(error))
            self.finish()
        try:
            dom = impl.createDocument(None, 'result', None)
            top_element = dom.documentElement
            itemAuth =  CreateXMLTag(dom,'auth','0')
            itemStatus =  CreateXMLTag(dom,'status','0')
            top_element.appendChild(itemAuth)
            top_element.appendChild(itemStatus)
            self.write(dom.toxml("utf-8"))
        except Exception,e:
            ErrorHandler(self,'PostMessage.onResponse()',e)
        finally:
            self.finish()

class GetMessage(BaseHandler):
    @CheckSession
    @tornado.web.asynchronous
    def post(self):    
        try:
            session = application.session_manager.get(self)
            uid = session['uid']
            dvc = session['dvc']
            _to = "%s@%s" % (uid,dvc)
            self.db.Messages.find({'$and':[{'to':_to},{'status':1}]},callback=self.onResponse)
        except Exception,e:
            ErrorHandler(self,'GetMessage.post()',e)
            self.finish()
    def onResponse(self,response,error):
        if error:
            ErrorHandler(self,'GetMessage.onResponse()','Get message error:%s' % str(error))
        try:
            #self.write(str(response))
            dom = impl.createDocument(None, 'result', None)
            top_element = dom.documentElement
            itemAuth =  CreateXMLTag(dom,'auth','0')
            strDataBegin = "<messages>"
            strDataEnd = "</messages>"
            strMessages = ""
            for message in response:
                strMessages += "<message><id>%s</id><action>%s</action></message>" % (message['_id'],message['msg'])
            strData = "%s%s%s" % (strDataBegin,strMessages,strDataEnd)
            dataDom = parseString(strData)
            data = dataDom.documentElement
        
            top_element.appendChild(itemAuth)
            top_element.appendChild(data)
            self.write(dom.toxml("utf-8"))
        except Exception,e:
            ErrorHandler(self,'GetMessage.onResponse()',e)
        finally:
            self.finish()

class MessageDone(BaseHandler):
    @CheckSession
    @tornado.web.asynchronous
    def post(self):
        mid = self.get_argument('mid')
        spec = {'_id':pymongo.objectid.ObjectId(mid)}
        try:
            self.db.Messages.update(spec,{"$set":{"status":0}},callback=self.onResponse)
        except Exception,e:
            ErrorHandler(self,'MessageDone.post()',e)
            self.finish()
    def onResponse(self,response,error):
        if error or response[0].get('ok') != 1:
            ErrorHandler(self,'MessageDone.onResponse()','update message status error:%s' % str(error))
            self.finish()
        try:
            dom = impl.createDocument(None, 'result', None)
            top_element = dom.documentElement
            itemAuth =  CreateXMLTag(dom,'auth','0')
            itemStatus = CreateXMLTag(dom,'status','0')
            
            top_element.appendChild(itemAuth)
            top_element.appendChild(itemStatus)
            self.write(dom.toxml("utf-8"))
        except Exception,e:
            ErrorHandler(self,'MessageDone.onResponse()',e)
        finally:
            self.finish()

class RemoveData(BaseHandler):
    #@tornado.web.asynchronous
    def get(self):
        try:
            self.db.Contents.remove(callback=self.onResponse)
            self.db.Devices.remove(callback=self.onResponse)
            self.db.Messages.remove(callback=self.onResponse)
            self.write("Data is removed!")
        except Exception,e:
            self.write("Error happend while removing data!\n Error: %s " % e)
class GetSession(BaseHandler):
    @tornado.web.asynchronous
    def post(self):
        sid = self.get_argument('sid')
        try:
            session= application.session_manager.get(self)
            self.write(session)
        except Exception,e:
            ErrorHandler(self,'GetSession.post()',e)            
        finally:
            self.finish()
class MainHandler(BaseHandler):
    #@CheckSession
    @tornado.web.asynchronous
    def post(self):
        self.doProcess(callback=self.onWaiting)
    def doProcess(self,callback):
        try:
            #a = 10/0
            dom = impl.createDocument(None, 'result', None)
            top_element = dom.documentElement
            itemAuth =  CreateXMLTag(dom,'auth','0')
            strDataBegin = "<data>"
            strDataEnd = "</data>"

            strRecord1 = "<container id='00001'><name>VDO</name></container>"
            strRecord2 = "<item id='00002'><name>Top Gun</name></item>"
            strData = strDataBegin + strRecord1 + strRecord2 + strDataEnd

            dataDom = parseString(strData)
            data = dataDom.documentElement
        
            top_element.appendChild(itemAuth)
            top_element.appendChild(data)
#            self.write(dom.toxml("utf-8"))
            callback(dom)
        except Exception,e:
            ErrorHandler(self,'MainHandler.get()',e)
            self.finish()
    def onResponse(self,response,error=None):
        if error:
            ErrorHandler(self,'MainHandler.onResponse()',error)
        else:
           if response:
               self.set_header('Content-Type','text/xml')
               self.write(response.toxml("utf-8"))
        self.finish()               
    

class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", MainHandler),
            (r"/login",LoginHandler),
            (r"/comparedevicemd5",CompareDeviceMD5),
            (r"/comparecontentsmd5",CompareContentsMD5),
            (r"/sync",SYNC),
            (r"/postmessage",PostMessage),
            (r"/getmessage",GetMessage),
            (r"/messagedone",MessageDone),
            (r"/getSession",GetSession),
            (r"/removedata",RemoveData)    #need to be comment out when this is in production since this is only for debug!!
        ]
        tornado.web.Application.__init__(self, handlers, **settings)

application = Application()
def main():
    tornado.options.parse_command_line()
    application.session_manager =  session.TornadoSessionManager(settings["cookie_secret"],settings["session_cache"],settings["session_expire"])
    application.log_manager = logger.logger()
    application.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()



if __name__ == "__main__":
    print "File Sync Server Started..."
    main()
    #http_server.listen(8888)
    #tornado.ioloop.IOLoop.instance().start()
