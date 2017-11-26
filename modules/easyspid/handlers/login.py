from response import ResponseObj
import tornado.web
import tornado.gen
import tornado.ioloop
import tornado.concurrent
import tornado.httpclient
import logging
from lib.customException import ApplicationException
import asyncio
from easyspid.handlers.authnreqBuild import authnreqBuildhandler
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
from onelogin.saml2.auth import OneLogin_Saml2_Auth
import globalsObj
import easyspid.lib.easyspid
from easyspid.lib.utils import Saml2_Settings, waitFuture
from easyspid.handlers.getMetadata import getMetadatahandler

class loginhandler(authnreqBuildhandler):

    def __init__(self, *args, **kwds):
        super().__init__(*args, **kwds)

    #get
    async def get(self, sp):
        x_real_ip = self.request.headers.get("X-Real-IP")
        self.remote_ip = x_real_ip or self.request.remote_ip
        self.set_header('Content-Type', 'application/json; charset=UTF-8')
        self.set_default_headers()

        idp = self.get_argument('idp')
        attributeIndex = self.get_argument('attrindex')
        binding = self.get_argument('binding')
        srelay = self.get_argument('srelay')

        task1 = asyncio.ensure_future(easyspid.lib.easyspid.spSettings(sp, idp, close = True))
        task2 = asyncio.ensure_future(self.dbobjSaml.execute_statment("get_prvd_metadta('%s')" % idp))

        sp_settings = await task1
        idp_metadata = getMetadatahandler.getMetadata(await task2)

        response_obj = await asyncio.get_event_loop().run_in_executor(self.executor, self.loginAuthnReq, sp_settings,
                                idp_metadata, attributeIndex, binding, srelay)

        if response_obj.error.httpcode == 200 and binding == 'redirect':
            asyncio.ensure_future(self.writeLog(response_obj), loop = globalsObj.ioloop)
            self.set_header('Content-Type', 'text/html; charset=UTF-8')
            self.set_header('Location', response_obj.result.redirectTo)
            self.set_status(303)
            self.finish()
            return

        elif response_obj.error.httpcode == 200 and binding == 'post':
            asyncio.ensure_future(self.writeLog(response_obj), loop = globalsObj.ioloop)
            self.set_header('Content-Type', 'text/html; charset=UTF-8')
            self.set_status(response_obj.error.httpcode)
            self.write(response_obj.result.postTo)
            self.finish()
            return

        asyncio.ensure_future(self.writeLog(response_obj), loop = globalsObj.ioloop)
        super().writeResponse(response_obj)

    def loginAuthnReq(self, sp_settings, idp_metadata, attributeIndex, binding, srelay_cod):
        try:

            if binding == 'redirect':
                authn_request = authnreqBuildhandler.buildAthnReq(self, sp_settings, attributeIndex, signed=False)
            elif binding == 'post':
                authn_request = authnreqBuildhandler.buildAthnReq(self, sp_settings, attributeIndex, signed=True)

            bindingMap = {'redirect':OneLogin_Saml2_Constants.BINDING_HTTP_REDIRECT,
                          'post': OneLogin_Saml2_Constants.BINDING_HTTP_POST}

            if (sp_settings['error'] == 0 and sp_settings['result'] is not None
                and idp_metadata.error.code == '200' and authn_request.error.code == '200'):

                sp = sp_settings['result']['sp']['cod_sp']
                idp = sp_settings['result']['idp']['cod_idp']

                # get relay state
                task  = asyncio.run_coroutine_threadsafe(self.dbobjSaml.execute_statment("get_service(%s, '%s', '%s')" %
                             ('True', srelay_cod, sp)), globalsObj.ioloop)
                #assert not task.done()
                #srelay = task.result()
                srelay = waitFuture(task)

                if srelay['error'] == 0 and srelay['result'] is None:
                    response_obj = ResponseObj(httpcode=404)
                    response_obj.setError('easyspid113')
                    return response_obj

                elif srelay['error'] > 0:
                    response_obj = ResponseObj(httpcode=500, debugMessage=sp_settings['result'])
                    response_obj.setError("easyspid105")
                    return response_obj

            #if (sp_settings['error'] == 0 and sp_settings['result'] is not None
                #and idp_metadata.error.code == '200' and authn_request.error.code == '200'):

                idp_data = OneLogin_Saml2_IdPMetadataParser.parse(idp_metadata.result.metadata,
                        required_sso_binding=bindingMap[binding], required_slo_binding=bindingMap[binding])
                idp_settings = idp_data['idp']

                # fake authn_request
                req = {"http_host": "",
                    "script_name": "",
                    "server_port": "",
                    "get_data": "",
                    "post_data": ""}

                settings = sp_settings['result']
                if 'entityId' in idp_settings:
                    settings['idp']['entityId'] = idp_settings['entityId']
                if 'singleLogoutService' in idp_settings:
                    settings['idp']['singleLogoutService'] = idp_settings['singleLogoutService']
                if 'singleSignOnService' in idp_settings:
                    settings['idp']['singleSignOnService'] = idp_settings['singleSignOnService']
                if 'x509cert' in idp_settings:
                    settings['idp']['x509cert'] = idp_settings['x509cert']

                auth = OneLogin_Saml2_Auth(req, sp_settings['result'])
                spSettings = Saml2_Settings(sp_settings['result'])

                sign_alg = (spSettings.get_security_data())['signatureAlgorithm']

                # build login message
                # redirect binding
                if binding == 'redirect':
                    saml_request = OneLogin_Saml2_Utils.deflate_and_base64_encode(authn_request.result.authnrequest)
                    parameters = {'SAMLRequest': saml_request}
                    parameters['RelayState'] = srelay['result'][0]['relay_state']
                    auth.add_request_signature(parameters, sign_alg)
                    redirectLocation = auth.redirect_to(auth.get_sso_url(), parameters)

                    response_obj = ResponseObj(httpcode=200)
                    response_obj.setError('200')
                    response_obj.setResult(redirectTo = redirectLocation, jwt=authn_request.result.jwt)

                # POST binding
                elif binding == 'post':
                    saml_request_signed = OneLogin_Saml2_Utils.b64encode(authn_request.result.authnrequest)
                    relay_state = OneLogin_Saml2_Utils.b64encode(srelay['result'][0]['relay_state'])
                    idpsso = idp_settings['singleSignOnService']['url']

                    try:
                        with open(os.path.join(globalsObj.rootFolder, globalsObj.easyspid_postFormPath), 'r') as myfile:
                            post_form = myfile.read().replace('\n', '')
                    except:
                        with open(globalsObj.easyspid_postFormPath, 'r') as myfile:
                            post_form = myfile.read().replace('\n', '')

                    post_form = post_form.replace("%IDPSSO%",idpsso)
                    post_form = post_form.replace("%AUTHNREQUEST%",saml_request_signed)
                    post_form = post_form.replace("%RELAYSTATE%",relay_state)

                    response_obj = ResponseObj(httpcode=200)
                    response_obj.setError('200')
                    response_obj.setResult(postTo = post_form, jwt=authn_request.result.jwt)

            elif sp_settings['error'] == 0 and sp_settings['result'] is None:
                response_obj = ResponseObj(httpcode=404)
                response_obj.setError('easyspid101')

            elif sp_settings['error'] > 0:
                response_obj = ResponseObj(httpcode=500, debugMessage=sp_settings['result'])
                response_obj.setError("easyspid105")

        except tornado.web.MissingArgumentError as error:
            response_obj = ResponseObj(debugMessage=error.log_message, httpcode=error.status_code,
                                       devMessage=error.log_message)
            response_obj.setError(str(error.status_code))
            logging.getLogger(__name__).error('%s'% error,exc_info=True)

        except ApplicationException as inst:
            response_obj = ResponseObj(httpcode=500)
            response_obj.setError(inst.code)
            #responsejson = response_obj.jsonWrite()
            logging.getLogger(__name__).error('Exception',exc_info=True)

        except Exception as inst:
            response_obj = ResponseObj(httpcode=500)
            response_obj.setError('500')
            logging.getLogger(__name__).error('Exception',exc_info=True)

        finally:
            logging.getLogger(__name__).warning('easyspid/loginAuthnReq handler executed')

        return response_obj
