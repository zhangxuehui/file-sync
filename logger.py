import syslog
class Priorities:
    LOG_EMERG = 0
    LOG_ALERT = 1
    LOG_CRIT = 2
    LOG_ERR = 3
    LOG_WARNING = 4
    LOG_NOTICE = 5
    LOG_INFO = 6
    LOG_DEBUG = 7
class logger():
   def __init__(self):
        syslog.openlog("DLNA-Server",syslog.LOG_PID,syslog.LOG_USER)
   def log(self,priority,message):
       if priority < 7 or priority != None:
           syslog.syslog(priority,message)
       else:
           syslog.syslog(syslog.LOG_INFO,message)


