import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), "lib"))
sys.path.append(os.path.join(os.path.dirname(__file__), "modules"))

import socket
import tornado.ioloop
import tornado.web
import tornado.httpserver
import tornado.util
import tornado.netutil
import tornado.process
import logging.config
from concurrent.futures import ThreadPoolExecutor
#from tornado.platform.asyncio import AsyncIOMainLoop
import jsonpickle as jsonpickle
import re
#import asyncpg
#import asyncio

"""
Add project path to sys.path
Load default logging file config
"""
path = os.path.dirname(os.path.realpath(__file__))
logging.config.fileConfig(fname=(path+'/conf/logging.ini'))

"""
Set default server config path
"""
import globalsObj
import commonlib

"""
Parse configuration files
"""
#write root location
globalsObj.rootFolder = os.path.dirname(os.path.realpath(__file__))+'/'
globalsObj.options = commonlib.commandLine(globalsObj.CONFIG_FILE_PATH)
globalsObj.configuration = commonlib.configure(globalsObj.CONFIG_FILE_PATH, globalsObj.options.filename)
try:
    logging.config.fileConfig(fname=(path+'/'+globalsObj.configuration.get('logging','conf')),disable_existing_loggers=False)
except:
    logging.config.fileConfig(fname=(globalsObj.configuration.get('logging','conf')),disable_existing_loggers=False)
globalsObj.ws_configuration = commonlib.configure(globalsObj.configuration.get('wspath','conf'))
globalsObj.errors_configuration = commonlib.configure(globalsObj.configuration.get('errors','conf'))

"""
core handlers
"""
from handle import VersionHandler
from handle import MainHandler
from handle import StaticHandler

"""
modules handlers
importa tutti i file che si trovano nelle cartelle handlers dei moduli
"""
modules_to_import = list()
with os.scandir(os.path.join(os.path.dirname(__file__), "modules")) as it:
    for module in it:
        if not module.name.startswith('.') and not module.name.startswith('_') and module.is_dir():
            tmp  = {'from': module.name+'.handlers', 'import': list()}
            with os.scandir(os.path.join(module.path, 'handlers')) as it2:
                for module2 in it2:
                    if not module2.name.startswith('.') and not module2.name.startswith('_') and module2.is_file():
                        tmp['import'].append(re.sub(r'\.py$', '', module2.name))
            tmp['import'] = ', '.join(tmp['import'])
            modules_to_import.append(tmp)

for module in modules_to_import:
    exec("from %s import %s" % (module['from'], module['import']))
    logging.getLogger(__name__).info("Loaded module %s" % module['from'])

#from sample.handlers import samplehandler
#from httpClientAsync.handlers import httpClientAsyncHandler
#from jwtoken.handlers import jwtokenhandler
#from easyspid.handlers import easyspidhandler

class WebApp(tornado.web.Application):
    def __init__(self, configuration, ws_configuration):

        self.globalsObj = globalsObj
        """ configure TCP server """
        try:
            """ Building URL """
            handlers = []
            for i, val in enumerate(ws_configuration.sections()):
                if val != 'conf':
                    tempDict = dict(ws_configuration.items(val))
                    temp = ""
                    for j, val2 in enumerate(tempDict.keys()):
                        temp += "%s=%s," % (val2,tempDict[val2])
                    temp = temp.strip(',')
                    urlTemp = "tornado.web.URLSpec(%s)" % (temp)
                    handlers.append(eval(urlTemp))
                    logging.getLogger(__name__).info("Created API. %s" % temp)

            """ create web application """
            super(self.__class__, self).__init__(handlers,
                    debug=configuration.getboolean('Application','debug'),
                    autoreload=configuration.getboolean('Application','autoreload'))
            self.executor = ThreadPoolExecutor(max_workers=configuration.getint('Application','max_workers'))

        except tornado.web.ErrorHandler as error:
            rootLogger.error("Tornado web error: %s" % (error))


#create postgresql pool and assign to webapp.pool attribute
#async def create_pool(webapp):
#    webapp.pool = await asyncpg.create_pool(user='root', password='pippo',
#                         database='easyspid', host='127.0.0.1')

if __name__ == '__main__':
    rootLogger = logging.getLogger(__name__)

    # install async loop
    #AsyncIOMainLoop().install()
    #ioloop = asyncio.get_event_loop()
    # set debug
    #ioloop.set_debug('enabled')

    tcp_conf = dict(globalsObj.configuration.items('TCP'))
    # write pid file
    commonlib.writePid(globalsObj.configuration.get('pid','file'))

    # create app
    webapp = WebApp(globalsObj.configuration, globalsObj.ws_configuration)

    # set backend to serilize objects
    jsonpickle.set_preferred_backend('simplejson')
    jsonpickle.set_encoder_options('simplejson', ensure_ascii=True, indent=4)

    try:
        sockets = tornado.netutil.bind_sockets(tcp_conf['port'],tcp_conf['address'], family=socket.AF_INET)

        rootLogger.warning("Found %s processor/s" % (tornado.process.cpu_count()))
        if (tcp_conf['num_processes'] == '0'):
            rootLogger.warning("Starting %s process/es listening on address %s, port %s"
                     % (tornado.process.cpu_count(), tcp_conf['address'], tcp_conf['port']))
        else:
            rootLogger.warning("Starting %s process/es listening on address %s, port %s"
                     % (tcp_conf['num_processes'], tcp_conf['address'], tcp_conf['port']))

        #asyncio doesn't work with multiprocess
        tornado.process.fork_processes(int(tcp_conf['num_processes']))
        rootLogger.warning("Started tornado process #%s" % (tornado.process.task_id()+1))

        server = tornado.httpserver.HTTPServer(webapp,
                xheaders=globalsObj.configuration.getboolean('HTTP','xheaders'),
                protocol=globalsObj.configuration.get('HTTP','protocol'))

        server.add_sockets(sockets)

        """ main loop """
        #ioloop.run_until_complete(create_pool(webapp))
        #ioloop.run_forever()

        tornado.ioloop.IOLoop.configure('tornado.platform.asyncio.AsyncIOLoop')
        mainIOLoop = tornado.ioloop.IOLoop.current()
        mainIOLoop.start()

    except socket.error as error:
        rootLogger.error("error on server socket: %s" % (error))
