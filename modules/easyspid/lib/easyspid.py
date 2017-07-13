import globalsObj
import commonlib as commonlib
import easyspid.lib.database
from response import ResponseObj
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
import easyspid.lib.database

ESPID_ERRORS_FILE_PATH = "modules/easyspid/conf/errors.ini"
ESPID_CONFIG_FILE_PATH = "modules/easyspid/conf/easyspid.ini"

# carica le configurazioni globali e locali del modulo
try:
    easyspid_file_configuration = commonlib.configure(ESPID_CONFIG_FILE_PATH, globalsObj.configuration.get('easyspid','conf'))
except BaseException as error:
    easyspid_file_configuration = commonlib.configure(ESPID_CONFIG_FILE_PATH)

# carica i messaggi di errore del modulo
easyspid_error_configuration = commonlib.configure(ESPID_ERRORS_FILE_PATH)

# istanzia le sezioni del fle di configurazione nel file globalsObj
globalsObj.easyspid_DbMaster_conf = dict(easyspid_file_configuration.items('DbMaster'))
globalsObj.easyspid_DbSlave_conf = dict(easyspid_file_configuration.items('DbSlave'))
globalsObj.easyspid_postFormPath = easyspid_file_configuration.get('AuthnRequest','postFormPath')

# istanzia tutte le sezioni degli errori nel file globalsObj
for i, val in enumerate(easyspid_error_configuration.sections()):
    if val != 'conf':
        globalsObj.errors_configuration.add_section(val)
        tempDict = dict(easyspid_error_configuration.items(val))
        for j, val2 in enumerate(tempDict.keys()):
            globalsObj.errors_configuration.set(val, val2, tempDict[val2])

## crea il pool per questo modulo
try:
    globalsObj.DbConnections
except Exception as error:
    globalsObj.DbConnections = dict()

# connect to DB master
dsnMaster = "host=" + easyspid_file_configuration.get('DbMaster','host') + \
    " port=" + easyspid_file_configuration.get('DbMaster','port') + \
    " dbname=" + easyspid_file_configuration.get('DbMaster','dbname')+ \
    " user=" + easyspid_file_configuration.get('DbMaster','user') + \
    " password=" + easyspid_file_configuration.get('DbMaster','password') + \
    " application_name=" + easyspid_file_configuration.get('DbMaster','application_name')

globalsObj.DbConnections['samlMasterdsn'] = dsnMaster

# connect to DB slave
dsnSlave = "host=" + easyspid_file_configuration.get('DbSlave','host') + \
    " port=" + easyspid_file_configuration.get('DbSlave','port') + \
    " dbname=" + easyspid_file_configuration.get('DbSlave','dbname')+ \
    " user=" + easyspid_file_configuration.get('DbSlave','user') + \
    " password=" + easyspid_file_configuration.get('DbSlave','password') + \
    " application_name=" + easyspid_file_configuration.get('DbSlave','application_name')

globalsObj.DbConnections['samlSlavedsn'] = dsnSlave

globalsObj.DbConnections['samlDbPollMaster'] = {'max_conn': easyspid_file_configuration.getint('dbpool','max_conn'),
                                                'min_conn': easyspid_file_configuration.getint('dbpool','min_conn'),
                                                'dsn': dsnMaster}

globalsObj.DbConnections['samlDbPollSlave'] = {'max_conn': easyspid_file_configuration.getint('dbpool','max_conn'),
                                               'min_conn': easyspid_file_configuration.getint('dbpool','min_conn'),
                                                'dsn': dsnSlave}

# inizializza dB object
globalsObj.DbConnections['samlDb'] = easyspid.lib.database.Database()
globalsObj.DbConnections['samlDb'].prepare_stmts()

# set some settings
globalsObj.easyspidSettings = dict()
globalsObj.easyspidSettings['idp'] = {
    "entityId": "https://app.onelogin.com/saml/metadata/<onelogin_connector_id>",
    "singleSignOnService": {
      "url": "https://app.onelogin.com/trust/saml2/http-post/sso/<onelogin_connector_id>",
      "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    },
    "singleLogoutService": {
      "url": "https://app.onelogin.com/trust/saml2/http-redirect/slo/<onelogin_connector_id>",
      "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    },
    "x509cert": "<onelogin_connector_cert>"
  }


def spSettings(cod_sp, cod_idp = None, close = True):
    result = {'error':0, 'result': None}

    # acquisisci una connessione dal pool
    #if conn is None:
    #    conn = easyspid.lib.database.Database(globalsObj.DbConnections['samlDbPollSlave']['pool'])
    #sp_settings = conn.get_sp_settings(cod_sp, close)

    dbobj = globalsObj.DbConnections['samlDb']
    sp_settings = dbobj.makeQuery("EXECUTE get_sp_settings(%s)",
                        [cod_sp],type = dbobj.stmts['get_providers']['pool'], close=close)

    if sp_settings['error'] == 0 and sp_settings['result'] != None:
        # genera risposta tutto ok
        sp_settings['result']['settings']['idp'] = globalsObj.easyspidSettings['idp']
        sp_settings['result']['settings']['sp']['x509cert'] = sp_settings['result']['public_key']
        sp_settings['result']['settings']['sp']['privateKey'] = sp_settings['result']['private_key']
        sp_settings['result']['settings']['sp']['x509cert_fingerprint'] = sp_settings['result']['fingerprint']
        sp_settings['result']['settings']['sp']['x509cert_fingerprintalg'] = sp_settings['result']['fingerprintalg']
        sp_settings['result']['settings']['security'] = sp_settings['result']['advanced_settings']['security']
        sp_settings['result']['settings']['contactPerson'] = sp_settings['result']['advanced_settings']['contactPerson']
        sp_settings['result']['settings']['organization'] = sp_settings['result']['advanced_settings']['organization']

        if cod_idp != None:
            #idp_metadata = globalsObj.DbConnections['samlSlave'].get_prvd_metadta(cod_idp)
            #idp_metadata = conn.get_prvd_metadta(cod_idp, close)

            idp_metadata = dbobj.makeQuery("EXECUTE get_prvd_metadta(%s)",
                        [cod_idp],type = dbobj.stmts['get_providers']['pool'], close=close)

            if idp_metadata['error'] == 0 and idp_metadata['result'] != None:

                metadata = idp_metadata['result']['xml']
                idp_data = OneLogin_Saml2_IdPMetadataParser.parse(metadata)
                idp_settings = idp_data['idp']

                if 'entityId' in idp_settings:
                    sp_settings['result']['settings']['idp']['entityId'] = idp_settings['entityId']
                if 'singleLogoutService' in idp_settings:
                    sp_settings['result']['settings']['idp']['singleLogoutService'] = idp_settings['singleLogoutService']
                if 'singleSignOnService' in idp_settings:
                    sp_settings['result']['settings']['idp']['singleSignOnService'] = idp_settings['singleSignOnService']
                if 'x509cert' in idp_settings:
                    sp_settings['result']['settings']['idp']['x509cert'] = idp_settings['x509cert']

                sp_settings['result']['settings']['idp']['x509cert_fingerprint'] = idp_metadata['result']['fingerprint']
                sp_settings['result']['settings']['idp']['x509cert_fingerprintalg'] = idp_metadata['result']['fingerprintalg']
                sp_settings['result']['settings']['idp']['metadata'] = metadata

                result['result'] = sp_settings['result']['settings']
                return result

            elif idp_metadata['error'] > 0:
                result['error'] = 1
                response_obj = ResponseObj(debugMessage=idp_metadata['result'].pgerror, httpcode=500,
                            devMessage=("PostgreSQL error code: %s" % idp_metadata['result'].pgcode))
                response_obj.setError('easyspid105')
                result['result'] = response_obj

            else:
                result['error'] = idp_metadata['error']
                result['result'] = idp_metadata['result']
        else:
            result['result'] = sp_settings['result']['settings']
            return result

    elif sp_settings['error'] > 0:
        result['error'] = 1
        response_obj = ResponseObj(debugMessage=sp_settings['result'].pgerror, httpcode=500,
                    devMessage=("PostgreSQL error code: %s" % sp_settings['result'].pgcode))
        response_obj.setError('easyspid105')
        result['result'] = response_obj

    else:
        result['error'] = sp_settings['error']
        result['result'] = sp_settings['result']

    return result