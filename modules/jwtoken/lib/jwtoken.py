import globalsObj
import commonlib as commonlib
#import jwtoken.lib.database
import database
import jwtoken.lib.statements
import os
import logging


JWT_ERRORS_FILE_PATH = os.path.join(globalsObj.modules_basedir, "jwtoken/conf/errors.ini")
JWT_CONFIG_FILE_PATH = os.path.join(globalsObj.modules_basedir, "jwtoken/conf/jwtoken.ini")

# carica le configurazioni globali e locali del modulo
jwtoken_file_configuration = commonlib.configure(JWT_CONFIG_FILE_PATH)
if globalsObj.configuration.has_option('jwtoken','conf'):
    jwtoken_file_configuration = commonlib.configure(globalsObj.configuration.get('jwtoken','conf'),jwtoken_file_configuration)

# carica i messaggi di errore del modulo
jwtoken_error_configuration = commonlib.configure(JWT_ERRORS_FILE_PATH)

# istanzia le sezioni del fle di configurazione nel file globalsObj
globalsObj.jwtoken_DbMaster_conf = dict(jwtoken_file_configuration.items('DbMaster'))
globalsObj.jwtoken_originIP_header = jwtoken_file_configuration.get('proxy','originIP_header')


# istanzia tutte le sezioni degli errori nel file globalsObj
for i, val in enumerate(jwtoken_error_configuration.sections()):
    if val != 'conf':
        globalsObj.errors_configuration.add_section(val)
        tempDict = dict(jwtoken_error_configuration.items(val))
        for j, val2 in enumerate(tempDict.keys()):
            globalsObj.errors_configuration.set(val, val2, tempDict[val2])

## crea le connessini con il DB
# try:
#     globalsObj.DbConnections
# except Exception as error:
#     globalsObj.DbConnections = dict()


# dsnMaster = ("postgres://%s:%s@%s:%s/%s?application_name=%s" % (jwtoken_file_configuration.get('DbMaster','user'),
#             jwtoken_file_configuration.get('DbMaster','password'), jwtoken_file_configuration.get('DbMaster','host'),
#             jwtoken_file_configuration.get('DbMaster','port'), jwtoken_file_configuration.get('DbMaster','dbname'),
#             jwtoken_file_configuration.get('DbMaster','application_name')))
#
# globalsObj.DbConnections['jwtdsn'] = dsnMaster
#
# globalsObj.DbConnections['jwtDbPoll'] = {'max_conn': jwtoken_file_configuration.getint('dbpool','max_conn'),
#                                     'min_conn': jwtoken_file_configuration.getint('dbpool','min_conn'),
#                                       'dsn': dsnMaster}

dsnMaster = ("postgres://%s:%s@%s:%s/%s?application_name=%s" % (globalsObj.modules_configuration['jwtoken'].get('DbMaster','user'),
            globalsObj.modules_configuration['jwtoken'].get('DbMaster','password'),
            globalsObj.modules_configuration['jwtoken'].get('DbMaster','host'),
            globalsObj.modules_configuration['jwtoken'].get('DbMaster','port'),
            globalsObj.modules_configuration['jwtoken'].get('DbMaster','dbname'),
            globalsObj.modules_configuration['jwtoken'].get('DbMaster','application_name')))

pool_settings = {'max_conn': globalsObj.modules_configuration['jwtoken'].getint('dbpool','max_conn'),
                 'min_conn': globalsObj.modules_configuration['jwtoken'].getint('dbpool','min_conn')}

# inizializza Db object e pool
#globalsObj.DbConnections['jwtDb'] = jwtoken.lib.database.Database()
#pool = globalsObj.ioloop.run_until_complete(jwtoken.lib.database.init_pool(globalsObj.DbConnections['jwtDbPoll'],
#                               init = globalsObj.DbConnections['jwtDb'].prepare_statements))
#globalsObj.DbConnections['jwtDb'].set_pool(pool)

logging.getLogger(__name__).info('Initiating jwtoken DB poll ...')
globalsObj.DbConnections['jwtDb'] = database.Database(dsnMaster)
globalsObj.DbConnections['jwtDb'].stmts = jwtoken.lib.statements.stmts
globalsObj.ioloop.run_until_complete(globalsObj.DbConnections['jwtDb'].init_pool(pool_settings,
                               init = globalsObj.DbConnections['jwtDb'].prepare_statements))
logging.getLogger(__name__).debug('jwtoken DB poll loaded ...')
