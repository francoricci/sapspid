from response import ResponseObj
import os
import sys
import tornado.web
import tornado.gen
import tornado.ioloop
import tornado.concurrent
import tornado.httpclient
import logging
from lib.customException import ApplicationException
import asyncio
from easyspid.handlers.easyspidhandler import easyspidHandler
import globalsObj
import easyspid.lib.easyspid
from easyspid.lib.utils import Saml2_Settings, waitFuture
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.constants import OneLogin_Saml2_Constants
#from onelogin.saml2.response import OneLogin_Saml2_Response
#from onelogin.saml2.errors import OneLogin_Saml2_ValidationError
import xml.etree.ElementTree


class responseHandler(easyspidHandler):

    def __init__(self, *args, **kwds):
        super().__init__(*args, **kwds)

    #post
    async def post(self):
        x_real_ip = self.request.headers.get("X-Real-IP")
        self.remote_ip = x_real_ip or self.request.remote_ip
        self.set_header('Content-Type', 'application/json; charset=UTF-8')
        self.set_default_headers()

        response_obj = await asyncio.get_event_loop().run_in_executor(self.executor, self.processResponse,
                                globalsObj.easyspid_chkTime, globalsObj.easyspid_checkInResponseTo)

        if response_obj.error.httpcode == 200:
            asyncio.ensure_future(self.writeLog(response_obj), loop = globalsObj.ioloop)

            self.set_header('Content-Type', 'text/html; charset=UTF-8')
            self.set_status(response_obj.error.httpcode)
            self.write(self.postTo)
            self.finish()
            return

        asyncio.ensure_future(self.writeLog(response_obj), loop = globalsObj.ioloop)
        super().writeResponse(response_obj)

    def processResponse(self, chkTime=True, checkInResponseTo=True):

        try:
            # get response and Relay state
            responsePost = self.get_argument('SAMLResponse')
            srelayPost = self.get_argument('RelayState')

            # decode saml response to get idp code by entityId attribute
            response = responsePost
            try:
                 response = OneLogin_Saml2_Utils.decode_base64_and_inflate(responsePost)
            except Exception:
                 response = OneLogin_Saml2_Utils.b64decode(responsePost)
            try:
                 response = OneLogin_Saml2_Utils.b64decode(responsePost)
            except Exception:
                 pass

            #decode Relay state
            srelay = srelayPost
            try:
                 srelay = OneLogin_Saml2_Utils.decode_base64_and_inflate(srelayPost)
            except Exception:
                 pass
            try:
                 srelay = OneLogin_Saml2_Utils.b64decode(srelayPost)
            except Exception:
                 pass

            ## get sp by ID
            ns = {'md0': OneLogin_Saml2_Constants.NS_SAMLP, 'md1': OneLogin_Saml2_Constants.NS_SAML}
            parsedResponse = xml.etree.ElementTree.fromstring(response)
            issuer = parsedResponse.find("md1:Issuer", ns)
            inResponseTo = parsedResponse.get('InResponseTo')
            audience = parsedResponse.find('md1:Assertion/md1:Conditions/md1:AudienceRestriction/md1:Audience', ns)

            if issuer is None or audience is None:
                response_obj = ResponseObj(httpcode=401)
                response_obj.setError('easyspid118')
                return response_obj

            task1 = asyncio.run_coroutine_threadsafe(self.dbobjSaml.execute_statment("chk_idAssertion('%s')" %
                    inResponseTo), globalsObj.ioloop)
            task2 = asyncio.run_coroutine_threadsafe(self.dbobjSaml.execute_statment("get_provider_byentityid(%s, '%s')" %
                    ('True', '{'+(issuer.text.strip())+'}')),  globalsObj.ioloop)
            task3 = asyncio.run_coroutine_threadsafe(self.dbobjSaml.execute_statment("get_provider_byentityid(%s, '%s')" %
                    ('True', '{'+(audience.text.strip())+'}')),  globalsObj.ioloop)

            #assert not task1.done()
            #inResponseChk = task1.result()
            inResponseChk = waitFuture(task1)
            audienceChk = waitFuture(task3)
            spByAudience = None
            spByInResponseTo = None

            if inResponseChk['error'] == 0 and inResponseChk['result'] is not None:
                spByInResponseTo = inResponseChk['result'][0]['cod_sp']

            if audienceChk['error'] == 0 and audienceChk['result'] is not None:
                spByAudience = audienceChk['result'][0]['cod_provider']

            #check audinece
            if spByAudience is None:
                response_obj = ResponseObj(httpcode=404)
                response_obj.setError('easyspid115')
                return response_obj

            #check inresponse to
            if checkInResponseTo and spByAudience == spByInResponseTo:
                sp = spByAudience

            elif checkInResponseTo and spByAudience != spByInResponseTo:
                response_obj = ResponseObj(httpcode=401)
                response_obj.setError('easyspid110')
                return response_obj

            sp = spByAudience

            try:
                task = asyncio.run_coroutine_threadsafe(self.dbobjSaml.execute_statment("get_service(%s, '%s', '%s')" %
                    ('True', str(srelay), sp)),globalsObj.ioloop)
                #assert not task.done()
                #service = task.result()
                service = waitFuture(task)

                if service['error'] == 0 and service['result'] is not None:
                    # costruisci il routing
                    self.routing = dict()
                    self.routing['url'] = service['result'][0]['url']
                    self.routing['relaystate'] = srelay
                    self.routing['format'] = service['result'][0]['format']

                elif service['error'] > 0 or service['result'] is None:
                    response_obj = ResponseObj(httpcode=500, debugMessage=service['result'])
                    response_obj.setError("easyspid111")
                    return response_obj

            except Exception:
                pass

            idpEntityId = waitFuture(task2)

            if idpEntityId['error'] == 0 and idpEntityId['result'] is not None:
                idp_metadata = idpEntityId['result'][0]['xml']
                idp = idpEntityId['result'][0]['cod_provider']

            elif idpEntityId['error'] == 0 and idpEntityId['result'] is None:
                response_obj = ResponseObj(httpcode=404)
                response_obj.setError('easyspid103')
                return response_obj

            elif idpEntityId['error'] > 0:
                response_obj = ResponseObj(httpcode=500, debugMessage=idpEntityId['result'])
                response_obj.setError("easyspid105")
                return response_obj

            # get settings
            task = asyncio.run_coroutine_threadsafe(easyspid.lib.easyspid.spSettings(sp, idp, close = True), globalsObj.ioloop)
            sp_settings = waitFuture(task)

            if sp_settings['error'] == 0 and sp_settings['result'] != None:

                ## insert response into DB
                task = asyncio.run_coroutine_threadsafe(self.dbobjSaml.execute_statment("write_assertion('%s', '%s', '%s', '%s')" %
                        (str(response,'utf-8'), sp, idp, self.remote_ip)), globalsObj.ioloop)
                wrtAuthn = waitFuture(task)

                if wrtAuthn['error'] == 0:

                    if self.routing['format'] == 'saml':
                        return self.passthrough()

                    task = asyncio.run_coroutine_threadsafe(self.dbobjJwt.execute_statment("get_token_by_cod('%s')" %
                            (wrtAuthn['result'][0]['cod_token'])), globalsObj.ioloop)
                    #assert not task.done()
                    #jwt = task.result()
                    jwt = waitFuture(task)

                else:
                    response_obj = ResponseObj(httpcode=500, debugMessage=wrtAuthn['result'])
                    response_obj.setError("easyspid105")
                    logging.getLogger(__name__).error('Exception',exc_info=True)
                    return response_obj

                # create settings OneLogin dict
                settings = sp_settings['result']
                prvdSettings = Saml2_Settings(sp_settings['result'])

                #OneLoginResponse = OneLogin_Saml2_Response(prvdSettings, responsePost)

                #check status code
                # try:
                #     OneLoginResponse.check_status()
                # except OneLogin_Saml2_ValidationError as error:
                #     response_obj = ResponseObj(httpcode=401, debugMessage=error.args[0])
                #     response_obj.setError('easyspid107')
                #     return response_obj

                # #check audience
                # if not settings['sp']['entityId'] in OneLoginResponse.get_audiences():
                #     response_obj = ResponseObj(httpcode=401, debugMessage=OneLoginResponse.get_audiences())
                #     response_obj.setError('easyspid109')
                #     return response_obj

                chk = easyspid.lib.utils.validateAssertion(str(response,'utf-8'),
                                sp_settings['result']['idp']['x509cert_fingerprint'],
                                sp_settings['result']['idp']['x509cert_fingerprintalg'])

                chk['issuer'] = issuer.text.strip()
                chk['audience'] = audience.text.strip()

                if not chk['chkStatus']:
                    response_obj = ResponseObj(httpcode=401)
                    response_obj.setError('easyspid107')
                    return response_obj

                elif not chk['schemaValidate']:
                    response_obj = ResponseObj(httpcode=401)
                    response_obj.setError('easyspid104')
                    response_obj.setResult(responseValidate = chk)
                    return response_obj

                elif not chk['signCheck']:
                    response_obj = ResponseObj(httpcode=401)
                    response_obj.setError('easyspid106')
                    response_obj.setResult(responseValidate = chk)
                    return response_obj

                elif not chk['certAllowed'] and globalsObj.easyspid_checkCertificateAllowed:
                    response_obj = ResponseObj(httpcode=401)
                    response_obj.setError('easyspid116')
                    response_obj.setResult(responseValidate = chk)
                    return response_obj

                elif not chk['certValidity'] and globalsObj.easyspid_checkCertificateValidity:
                    response_obj = ResponseObj(httpcode=401)
                    response_obj.setError('easyspid117')
                    response_obj.setResult(responseValidate = chk)
                    return response_obj

                elif chkTime and not chk['chkTime']:
                    response_obj = ResponseObj(httpcode=401)
                    response_obj.setError('easyspid108')
                    return response_obj

                #elif chk['schemaValidate'] and chk['signCheck']:
                #    response_obj = ResponseObj(httpcode=200, ID = wrtAuthn['result'][0]['ID_assertion'])
                #    response_obj.setError('200')

                #get all attributes
                #attributes = OneLoginResponse.get_attributes()
                attributes = chk['serviceAttributes']
                attributes_tmp = dict()
                for key in attributes:
                    attributes_tmp[key] = attributes[key][0]
                attributes = attributes_tmp;

                # build response fprm
                try:
                    with open(os.path.join(globalsObj.modules_basedir, globalsObj.easyspid_responseFormPath), 'r') as myfile:
                        response_form = myfile.read()
                except:
                    with open(globalsObj.easyspid_responseFormPath, 'r') as myfile:
                        response_form = myfile.read()

                response_obj = ResponseObj(httpcode=200, ID = wrtAuthn['result'][0]['ID_assertion'])
                response_obj.setError('200')
                response_obj.setResult(attributes = attributes, jwt = jwt['result'][0]['token'], responseValidate = chk,
                        response = str(response, 'utf-8'), format = 'json')

                response_form = response_form.replace("%URLTARGET%",self.routing['url'])
                response_form = response_form.replace("%RELAYSTATE%",srelayPost)
                response_form = response_form.replace("%RESPONSE%",OneLogin_Saml2_Utils.b64encode(response_obj.jsonWrite()))
                self.postTo = response_form

            elif sp_settings['error'] == 0 and sp_settings['result'] == None:
                response_obj = ResponseObj(httpcode=404)
                response_obj.setError('easyspid114')

            elif sp_settings['error'] > 0:
                response_obj = sp_settings['result']

        except tornado.web.MissingArgumentError as error:
            response_obj = ResponseObj(debugMessage=error.log_message, httpcode=error.status_code,
                                       devMessage=error.log_message)
            response_obj.setError(str(error.status_code))
            logging.getLogger(__name__).error('%s'% error,exc_info=True)

        except ApplicationException as inst:
            response_obj = ResponseObj(httpcode=500)
            response_obj.setError(inst.code)
            logging.getLogger(__name__).error('Exception',exc_info=True)

        except Exception as inst:
            response_obj = ResponseObj(httpcode=500)
            response_obj.setError('500')
            logging.getLogger(__name__).error('Exception',exc_info=True)

        finally:
            logging.getLogger(__name__).warning('easyspid/processResponse handler executed')

        return response_obj

    def passthrough(self):
        try:
            try:
                with open(os.path.join(globalsObj.modules_basedir, globalsObj.easyspid_SAMLresponseFormPath), 'r') as myfile:
                    response_form = myfile.read()
            except:
                with open(globalsObj.easyspid_SAMLresponseFormPath, 'r') as myfile:
                    response_form = myfile.read()

            response_obj = ResponseObj(httpcode=200)
            response_obj.setError('200')
            response_obj.setResult(format = 'saml')

            response_form = response_form.replace("%URLTARGET%",self.routing['url'])
            response_form = response_form.replace("%RELAYSTATE%",self.routing['relaystate'])
            response_form = response_form.replace("%RESPONSE%",self.get_argument('SAMLResponse'))
            self.postTo = response_form

            return response_obj

        except Exception as inst:
            response_obj = ResponseObj(httpcode=500)
            response_obj.setError('500')
            logging.getLogger(__name__).error('Exception',exc_info=True)

            return response_obj