import globalsObj
import commonlib as commonlib
import jwtoken.lib.database
import os


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

# istanzia tutte le sezioni degli errori nel file globalsObj
for i, val in enumerate(jwtoken_error_configuration.sections()):
    if val != 'conf':
        globalsObj.errors_configuration.add_section(val)
        tempDict = dict(jwtoken_error_configuration.items(val))
        for j, val2 in enumerate(tempDict.keys()):
            globalsObj.errors_configuration.set(val, val2, tempDict[val2])

## crea le connessini con il DB
try:
    globalsObj.DbConnections
except Exception as error:
    globalsObj.DbConnections = dict()


dsnMaster = ("postgres://%s:%s@%s:%s/%s?application_name=%s" % (jwtoken_file_configuration.get('DbMaster','user'),
            jwtoken_file_configuration.get('DbMaster','password'), jwtoken_file_configuration.get('DbMaster','host'),
            jwtoken_file_configuration.get('DbMaster','port'), jwtoken_file_configuration.get('DbMaster','dbname'),
            jwtoken_file_configuration.get('DbMaster','application_name')))

globalsObj.DbConnections['jwtdsn'] = dsnMaster

globalsObj.DbConnections['jwtDbPoll'] = {'max_conn': jwtoken_file_configuration.getint('dbpool','max_conn'),
                                    'min_conn': jwtoken_file_configuration.getint('dbpool','min_conn'),
                                      'dsn': dsnMaster}

# inizializza Db object e pool
globalsObj.DbConnections['jwtDb'] = jwtoken.lib.database.Database()
pool = globalsObj.ioloop.run_until_complete(jwtoken.lib.database.init_pool(globalsObj.DbConnections['jwtDbPoll'],
                               init = globalsObj.DbConnections['jwtDb'].prepare_statements))
globalsObj.DbConnections['jwtDb'].set_pool(pool)
