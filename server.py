import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), "lib"))
sys.path.append(os.path.join(os.path.dirname(__file__), "modules"))

import configparser
import socket
import tornado.ioloop
import tornado.web
import tornado.httpserver
import tornado.util
import tornado.netutil
import tornado.process
import logging.config
from concurrent.futures import ThreadPoolExecutor
import jsonpickle as jsonpickle
import re
import globalsObj
import commonlib

#os.environ['PYTHONASYNCIODEBUG'] = '1'
#logging.basicConfig(level=logging.DEBUG)
#logging.getLogger('asyncio').setLevel(logging.WARNING)

"""
Get project path
Load default logging file config
"""
path = os.path.dirname(os.path.realpath(__file__))
defaultLoggingFile = os.path.join(path, 'conf', 'logging.ini')
defaultLoggingConfig = commonlib.incrementalIniFile(defaultLoggingFile)
logging.config.fileConfig(defaultLoggingConfig)

"""
Parse config files
"""
#write root location
globalsObj.rootFolder = path
globalsObj.options = commonlib.commandLine(globalsObj.CONFIG_FILE_PATH)
globalsObj.configuration = commonlib.configure(globalsObj.CONFIG_FILE_PATH, globalsObj.options.filename)

if os.path.exists(os.path.join(globalsObj.rootFolder, globalsObj.configuration.get('Application','modules_dir'))):
    globalsObj.modules_basedir = os.path.join(globalsObj.rootFolder, globalsObj.configuration.get('Application','modules_dir'))
else:
    globalsObj.modules_basedir = globalsObj.configuration.get('Application','modules_dir')

if os.path.isfile(os.path.join(path, globalsObj.configuration.get('logging','conf'))):
    globalsObj.loggingFile = os.path.join(path, globalsObj.configuration.get('logging','conf'))
else:
    globalsObj.loggingFile = globalsObj.configuration.get('logging','conf')


globalsObj.loggingConfig = commonlib.incrementalIniFile( globalsObj.loggingFile, defaultLoggingFile)
logging.config.fileConfig(globalsObj.loggingConfig, disable_existing_loggers=False)

"""
Load core server configuration
"""
globalsObj.ws_configuration = []
globalsObj.ws_configuration.append(commonlib.configure(globalsObj.configuration.get('wspath','conf')))
globalsObj.errors_configuration = commonlib.configure(globalsObj.configuration.get('errors','conf'))

"""
core handlers
"""
from handle import VersionHandler
from handle import MainHandler
from handle import StaticHandler

"""
modules handlers
imports all the modules foung in the handler's module subpath
"""
modules_to_import = list()
with os.scandir(globalsObj.modules_basedir) as it:
    for module in it:
        if not module.name.startswith('.') and not module.name.startswith('_') and module.is_dir():
            tmp  = {'from': module.name+'.handlers', 'import': list()}

            try:
                fname = os.path.join(globalsObj.modules_basedir, module.name, 'conf', 'logging.ini')
                if os.path.isfile(fname):
                    globalsObj.loggingConfig = commonlib.incrementalIniFile(fname, globalsObj.loggingConfig)
                    logging.getLogger(__name__).info("Read default logging module file %s" % (fname))
            except Exception as exc:
                '''
                Se un modulo definisce un file di logging nel path (del modulo) /conf/logging.ini
                Per funzionare deve importare in maniera corretta il logger root. Ovvero con formatter e handler
                Poi alla fine del caricamento dei moduli viene nuovamente imprtato il file di logging di base per
                ricaricare il root logger di default
                '''
                pass
                    #logging.getLogger('root').error('Errore nel caricamento della configurazione di logging' + repr(exc))

            with os.scandir(os.path.join(module.path, 'handlers')) as it2:
                for module2 in it2:
                    if not module2.name.startswith('.') and not module2.name.startswith('_') and module2.is_file():
                        if module2.name.endswith('.pyc') and not module2.name[:-4] in tmp['import']:
                            tmp['import'].append(re.sub(r'\.pyc$', '', module2.name))
                        elif module2.name.endswith('.py') and not module2.name[:-3] in tmp['import']:
                            tmp['import'].append(re.sub(r'\.py$', '', module2.name))

            wspath_name = os.path.join(globalsObj.modules_basedir, module.name, 'conf', 'wspath.ini')
            if os.path.isfile(wspath_name):
                globalsObj.ws_configuration.append(commonlib.configure(wspath_name))

            tmp['import'] = ', '.join(tmp['import'])
            modules_to_import.append(tmp)

"""
Load the final server configuration
"""
globalsObj.loggingConfig = commonlib.incrementalIniFile(globalsObj.loggingFile, globalsObj.loggingConfig)
logging.config.fileConfig(globalsObj.loggingConfig, disable_existing_loggers=False)
logging.getLogger(__name__).info("Read local logging file %s" % (globalsObj.loggingFile))

"""
Load the final wspath config to get the non-handled paths
"""
lastSection = configparser.ConfigParser()
lastSection.read_dict(globalsObj.wspathLast)
globalsObj.ws_configuration.append(lastSection)

for module in modules_to_import:
    exec("from %s import %s" % (module['from'], module['import']))
    logging.getLogger(__name__).info("Loaded module %s.%s" % (module['from'], module['import']))

class WebApp(tornado.web.Application):
    def __init__(self, configuration, ws_configuration_list):

        self.globalsObj = globalsObj
        """ configure TCP server """
        try:
            """ Building URL """
            handlers = []
            for ws_configuration in ws_configuration_list:
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

        #except tornado.web.ErrorHandler as error:
        except Exception as error:
            rootLogger.error("Tornado web error: %s" % (error))


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

    except Exception as exc:
        rootLogger.error("General error catch: %s" % (exc))
