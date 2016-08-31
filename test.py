import tornado.ioloop
import tornado.web
import session,time
import tornado.httpserver


settings = {}
settings["cookie_secret"] = '61oETzKXQAGaYdkL5gEmGeJJFuYh7EQnp2XdTP1o/Vo='
settings["session_dir"] = '/home/zhangxh/DLNAServer/sessions'
settings["session_expir"] = 30 #seconds


def checksession(uid,session_id,session):
    if session_id == None or session_id != session.session_id:
        #request auth at caller
        return False
    if session.get(uid)== None or  float(time.time())-float(session.get(uid)) > settings["session_expir"]:
        #request auth at caller
        return False
    #Pass, do whatever else at caller
    return True

def login(uid,pwd):
    #Call AUTH
    if uid=="Jazhang":
        return True
    else:
        return False

class MainHandler(tornado.web.RequestHandler):
    def get(self):
        uid = self.get_argument("uid")
        pwd = self.get_argument("pwd")
        session_id = self.get_argument("sid")
        cookie=""
        if self.get_secure_cookie(uid) != None:
            cookie = self.get_secure_cookie("Jazhang") 
        session = application.session_manager.get(self)
        self.write("Client Session: %s <br> Server Session: %s <br> Cookie: %s" % (session_id,session.session_id,cookie))
        if checksession(uid,session_id,session):
           self.write("You last login: %s <br> You session ID: %s " % (time.asctime(time.gmtime(float(session.get(uid)))),session.session_id))
           session[uid]=time.time()
        else:
            if login(uid,pwd):
                session[uid]=time.time()
                application.session_manager.set(self,session)
                self.set_secure_cookie(uid,session.session_id)
                self.write("New session is done<br> Session ID: %s" % session.session_id)
            else:
                self.write("No authorized user: %s <br> Session ID: %s " % (uid,session.session_id))
            
class User(tornado.web.RequestHandler):
    def get(self):
        session_id=self.get_argument("sid")
        application.session_manager.set(self,session)
        if session_id != session.session_id :
            self.write("Session ID doesn't match<br>")

        #self.session = session.TornadoSession(self.application.session_manager,self)
        self.write("Session ID: %s <br> HMAC: %s" % (session.session_id,session.hmac_digest))

application = tornado.web.Application([
    (r"/", MainHandler),
    (r"/user",User),
],**settings)
application.session_manager = session.TornadoSessionManager(settings["cookie_secret"], settings["session_dir"])

if __name__ == "__main__":
    http_server = tornado.httpserver.HTTPServer(application)
    http_server.listen(8888)
    tornado.ioloop.IOLoop.instance().start()
    print "Server started..."
