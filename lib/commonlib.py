import configparser
import os
import signal
import logging
import argparse

""" read config file """
def configure(default_file, local_file=None):

    Logger = logging.getLogger(__name__)
    file_parser = configparser.ConfigParser(allow_no_value=True)
    file_parser.add_section('conf')

    # try load default config file
    try:
        file_parser.read_file(open(default_file))
        file_parser.set('conf','default', default_file)
        Logger.warning("server deafult configuration file/s loaded "+ file_parser.get('conf','default'))
    except configparser.Error:
        Logger.error('Impossible to load ' + default_file + '. Check path and permissions')
        run = 0

    # try to load the local config file
    if(local_file != None):
        try:
            file_parser.read_file(open(local_file))
            file_parser.set('conf','local', local_file)
            Logger.warning("server local configuration file/s loaded "+ file_parser.get('conf','local'))
        except configparser.Error:
            Logger.warning('Impossible to load ' + local_file + '. Check path and permissions')
    else:
        file_parser.set('conf','local', 'none')

    return file_parser

""" write pid file """
def writePid(file):
    fileHandler = open(file,"w")
    pid = os.getpid()
    fileHandler.write(str(pid)+"\n")
    fileHandler.close()

""" send kill signal to a process with pid """
def kill(pid):
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass

""" send term signal to a process with pid """
def term(pid):
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass

def commandLine(configFile):
    cmd_line_parser = argparse.ArgumentParser(
		    description = 'Tornado Web Server')
    cmd_line_parser.add_argument("-c", "--conf", dest="filename",
		    metavar="FILE", help="server configuration file. Default: "+configFile)
    #cmd_line_parser.add_argument("-w", "--wspath", dest="wsfilename",
	#	    metavar="FILE", help="web services path configuration file. Default: "+CONFIG_WSPATH_PATH)
    options = cmd_line_parser.parse_args()
    return options
