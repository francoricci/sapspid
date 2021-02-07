from response import ResponseObj
import os
import tornado.web
import tornado.gen
import tornado.ioloop
import tornado.concurrent
import tornado.httpclient
import logging
import asyncio
from easyspid.handlers.easyspidhandler import easyspidHandler
import globalsObj
import easyspid.lib.easyspid
from easyspid.lib.utils import Saml2_Settings, waitFuture, getResponseError, goExit
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.constants import OneLogin_Saml2_Constants
import xml.etree.ElementTree
import commonlib


class responseHandler(easyspidHandler):

    def __init__(self, *args, **kwds):
        super().__init__(*args, **kwds)

    #post
    async def post(self):
        x_real_ip = self.request.headers.get(globalsObj.easyspid_originIP_header)
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

    @commonlib.inner_log
    def processResponse(self, chkTime=True, checkInResponseTo=True):

        try:
            # get response and Relay state
            responsePost = self.get_argument('SAMLResponse')
            srelayPost = self.get_argument('RelayState')

            # decode saml response
            #response = responsePost
            self.response = responsePost
            try:
                self.response = OneLogin_Saml2_Utils.decode_base64_and_inflate(responsePost)
            except Exception:
                try:
                    self.response = OneLogin_Saml2_Utils.b64decode(responsePost)
                except Exception:
                    pass

            # try:
            #     #response = OneLogin_Saml2_Utils.b64decode(responsePost)
            #     self.response = OneLogin_Saml2_Utils.b64decode(responsePost)
            # except Exception:
            #     pass

            ## parse XML and make some check
            ns = {'md0': OneLogin_Saml2_Constants.NS_SAMLP, 'md1': OneLogin_Saml2_Constants.NS_SAML}
            parsedResponse = xml.etree.ElementTree.fromstring(self.response)

            self.inResponseTo = parsedResponse.get('InResponseTo')
            self.ResponseID = parsedResponse.get('ID')
            issuer = self.issuer = parsedResponse.find("md1:Issuer", ns)
            if issuer is None:
                response_obj = ResponseObj(httpcode=401)
                response_obj.setError('easyspid118')
                return response_obj

            #spByInResponseTo = None
            # try to get sp searching a corresponding request and raise error if checkInResponseTo is True
            # inResponseChk = waitFuture(asyncio.run_coroutine_threadsafe(self.dbobjSaml.execute_statment("chk_idAssertion('%s')" %
            #             inResponseTo), globalsObj.ioloop))
            # if inResponseChk['error'] == 0 and inResponseChk['result'] is not None:
            #         spByInResponseTo = inResponseChk['result'][0]['cod_sp']
            #
            # elif checkInResponseTo and inResponseChk['error'] == 0 and inResponseChk['result'] == None:
            #     response_obj = ResponseObj(httpcode=404, ID = ResponseID)
            #     response_obj.setError('easyspid120')
            #     response_obj.setResult(response = str(response, 'utf-8'))
            #     return response_obj
            #
            # elif inResponseChk['error'] > 0:
            #     response_obj = ResponseObj(httpcode=500)
            #     response_obj.setError('easyspid105')
            #     response_obj.setResult(inResponseChk['result'])
            #     return response_obj

            # try to get sp searching a corresponding request and raise error if checkInResponseTo is True
            spByInResponseTo = self.chkExistsReq(checkInResponseTo)

            ### check StatusCode to find errors
            firstChk = easyspid.lib.utils.validateAssertion(str(self.response,'utf-8'), None, None)
            if not firstChk['chkStatus']:
                #get errors codes
                samlErrors = waitFuture(asyncio.run_coroutine_threadsafe(
                    getResponseError(parsedResponse, sp = spByInResponseTo, namespace = ns),
                    globalsObj.ioloop))

                if samlErrors['error'] == '0':
                    response_obj = ResponseObj(httpcode=400, ID = self.ResponseID)
                    response_obj.setError('easyspid121')
                    response_obj.setResult(response = str(self.response, 'utf-8'), format = 'json',
                            samlErrors = samlErrors['status'])

                    return self.formatError(response_obj, srelayPost, samlErrors['service'])

                elif samlErrors['error'] == 'easyspid114':
                    response_obj = ResponseObj(httpcode=404)
                    response_obj.setError('easyspid114')
                    return response_obj

                else:
                    response_obj = ResponseObj(httpcode=500)
                    response_obj.setError('500')
                    response_obj.setResult(samlErrors['error'])
                    return response_obj

            #decode Relay state
            #srelay = srelayPost
            self.srelay = srelayPost
            try:
                self.srelay = OneLogin_Saml2_Utils.decode_base64_and_inflate(srelayPost)
            except Exception:
                try:
                  self.srelay = OneLogin_Saml2_Utils.b64decode(srelayPost)

                except Exception:
                  pass

                #self.srelay = OneLogin_Saml2_Utils.b64decode(srelayPost)
                #pass
            # try:
            #      #srelay = OneLogin_Saml2_Utils.b64decode(srelayPost)
            #      self.srelay = OneLogin_Saml2_Utils.b64decode(srelayPost)
            # except Exception:
            #      pass

            ## get sp by ID
            #ns = {'md0': OneLogin_Saml2_Constants.NS_SAMLP, 'md1': OneLogin_Saml2_Constants.NS_SAML}
            #parsedResponse = xml.etree.ElementTree.fromstring(response)
            #issuer = self.issuer = parsedResponse.find("md1:Issuer", ns)
            #inResponseTo = parsedResponse.get('InResponseTo')

            #get audience
            audience = self.audience = parsedResponse.find('md1:Assertion/md1:Conditions/md1:AudienceRestriction/md1:Audience', ns)
            if audience is None:
                response_obj = ResponseObj(httpcode=401)
                response_obj.setError('easyspid118')
                return response_obj

            # if issuer is None or audience is None:
            #     response_obj = ResponseObj(httpcode=401)
            #     response_obj.setError('easyspid118')
            #     return response_obj

            #task1 = asyncio.run_coroutine_threadsafe(self.dbobjSaml.execute_statment("chk_idAssertion('%s')" %
            #        inResponseTo), globalsObj.ioloop)
            # task2 = asyncio.run_coroutine_threadsafe(self.dbobjSaml.execute_statment("get_provider_byentityid(%s, '%s')" %
            #         ('True', '{'+(self.issuer.text.strip())+'}')),  globalsObj.ioloop)
            #task3 = asyncio.run_coroutine_threadsafe(self.dbobjSaml.execute_statment("get_provider_byentityid(%s, '%s')" %
            #       ('True', '{'+(audience.text.strip())+'}')),  globalsObj.ioloop)

            #assert not task1.done()
            #inResponseChk = task1.result()
            #inResponseChk = waitFuture(task1)
            #audienceChk = waitFuture(task3)
            #spByAudience = None
            #spByInResponseTo = None

            #if inResponseChk['error'] == 0 and inResponseChk['result'] is not None:
            #    spByInResponseTo = inResponseChk['result'][0]['cod_sp']

            # if audienceChk['error'] == 0 and audienceChk['result'] is not None:
            #     spByAudience = audienceChk['result'][0]['cod_provider']

            #check audinece
            # if spByAudience is None:
            #     response_obj = ResponseObj(httpcode=404)
            #     response_obj.setError('easyspid115')
            #     return response_obj

            # get sp by audience
            spByAudience = self.getSpByAudience()

            #check inresponseTo and spByAudience == spByInResponseTo
            if checkInResponseTo and spByAudience == spByInResponseTo:
                sp = spByAudience

            elif checkInResponseTo and spByAudience != spByInResponseTo:
                response_obj = ResponseObj(httpcode=401)
                response_obj.setError('easyspid110')
                return response_obj

            sp = spByAudience

            # get service by sp and relay_state
            try:
                task = asyncio.run_coroutine_threadsafe(self.dbobjSaml.execute_statment("get_service(%s, '%s', '%s')" %
                    ('True', str(self.srelay), sp)),globalsObj.ioloop)
                #assert not task.done()
                #service = task.result()
                service = waitFuture(task)

                if service['error'] == 0 and service['result'] is not None:
                    # costruisci il routing
                    self.routing = dict()
                    self.routing['url'] = service['result'][0]['url']
                    self.routing['relaystate'] = self.srelay
                    self.routing['format'] = service['result'][0]['format']

                elif service['error'] > 0 or service['result'] is None:
                    response_obj = ResponseObj(httpcode=500, debugMessage=service['result'])
                    response_obj.setError("easyspid111")
                    return response_obj

            except Exception:
                pass

            # get IdP
            # idpEntityId = waitFuture(task2)
            #
            # if idpEntityId['error'] == 0 and idpEntityId['result'] is not None:
            #     idp_metadata = idpEntityId['result'][0]['xml']
            #     idp = idpEntityId['result'][0]['cod_provider']
            #
            # elif idpEntityId['error'] == 0 and idpEntityId['result'] is None:
            #     response_obj = ResponseObj(httpcode=404)
            #     response_obj.setError('easyspid103')
            #     return response_obj
            #
            # elif idpEntityId['error'] > 0:
            #     response_obj = ResponseObj(httpcode=500, debugMessage=idpEntityId['result'])
            #     response_obj.setError("easyspid105")
            #     return response_obj

            # get IdP and metadata
            (idp_metadata, idp) = self.getIdentyIdp()

            # get sp settings
            task = asyncio.run_coroutine_threadsafe(easyspid.lib.easyspid.spSettings(sp, idp, close = True), globalsObj.ioloop)
            sp_settings = waitFuture(task)

            if sp_settings['error'] == 0 and sp_settings['result'] != None:

                ## insert response into DB
                task = asyncio.run_coroutine_threadsafe(self.dbobjSaml.execute_statment("write_assertion('%s', '%s', '%s', '%s')" %
                        (str(self.response,'utf-8').replace("'", "''"), sp, idp, self.remote_ip)), globalsObj.ioloop)
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
                    logging.getLogger(type(self).__module__+"."+type(self).__qualname__).error('Exception',exc_info=True)
                    return response_obj

                # create settings OneLogin dict
                #settings = sp_settings['result']
                prvdSettings = Saml2_Settings(sp_settings['result'])

                chk = easyspid.lib.utils.validateAssertion(str(self.response,'utf-8'),
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

                #get all attributes
                attributes = chk['serviceAttributes']
                attributes_tmp = dict()
                for key in attributes:
                    attributes_tmp[key] = attributes[key][0]
                attributes = attributes_tmp;

                # build response form
                try:
                    with open(os.path.join(globalsObj.modules_basedir, globalsObj.easyspid_responseFormPath), 'rb') as myfile:
                        response_form = myfile.read().decode("utf-8")
                except:
                    with open(globalsObj.easyspid_responseFormPath, 'rb') as myfile:
                        response_form = myfile.read().decode("utf-8")

                response_obj = ResponseObj(httpcode=200, ID = wrtAuthn['result'][0]['ID_assertion'])
                response_obj.setError('200')
                response_obj.setResult(attributes = attributes, jwt = jwt['result'][0]['token'], responseValidate = chk,
                        response = str(self.response, 'utf-8'), format = 'json')

                response_form = response_form.replace("%URLTARGET%",self.routing['url'])
                response_form = response_form.replace("%RELAYSTATE%",srelayPost)
                response_form = response_form.replace("%RESPONSE%",OneLogin_Saml2_Utils.b64encode(response_obj.jsonWrite()))
                self.postTo = response_form

            elif sp_settings['error'] == 0 and sp_settings['result'] == None:
                response_obj = ResponseObj(httpcode=404)
                response_obj.setError('easyspid114')

            elif sp_settings['error'] > 0:
                #response_obj = sp_settings['result']
                response_obj = sp_settings

        except goExit as e:
            return e.expression

        except tornado.web.MissingArgumentError as error:
            response_obj = ResponseObj(debugMessage=error.log_message, httpcode=error.status_code,
                                       devMessage=error.log_message)
            response_obj.setError(str(error.status_code))
            logging.getLogger(type(self).__module__+"."+type(self).__qualname__).error('%s'% error,exc_info=True)

        except Exception as inst:
            response_obj = ResponseObj(httpcode=500)
            response_obj.setError('500')
            logging.getLogger(type(self).__module__+"."+type(self).__qualname__).error('Exception',exc_info=True)

        return response_obj

    @commonlib.inner_log
    def passthrough(self):
        try:
            try:
                with open(os.path.join(globalsObj.modules_basedir, globalsObj.easyspid_SAMLresponseFormPath), 'rb') as myfile:
                    response_form = myfile.read().decode("utf-8")
            except:
                with open(globalsObj.easyspid_SAMLresponseFormPath, 'rb') as myfile:
                    response_form = myfile.read().decode("utf-8")

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
            logging.getLogger(type(self).__module__+"."+type(self).__qualname__).error('Exception',exc_info=True)

            return response_obj

    @commonlib.inner_log
    def formatError(self, response_obj, srelay, url):
        try:

            # build response fprm
            try:
                with open(os.path.join(globalsObj.modules_basedir, globalsObj.easyspid_responseFormPath), 'rb') as myfile:
                    response_form = myfile.read().decode("utf-8")
            except:
                with open(globalsObj.easyspid_responseFormPath, 'rb') as myfile:
                    response_form = myfile.read().decode("utf-8")

            new_response_obj = ResponseObj(httpcode=200, ID =response_obj.id)
            new_response_obj.setError('200')
            new_response_obj.result = response_obj.result

            response_form = response_form.replace("%URLTARGET%", url)
            response_form = response_form.replace("%RELAYSTATE%", srelay)
            response_form = response_form.replace("%RESPONSE%", OneLogin_Saml2_Utils.b64encode(response_obj.jsonWrite()))
            self.postTo = response_form

            return new_response_obj

        except Exception as inst:
            response_obj = ResponseObj(httpcode=500)
            response_obj.setError('500')
            logging.getLogger(type(self).__module__+"."+type(self).__qualname__).error('Exception',exc_info=True)

            return new_response_obj

    @commonlib.inner_log
    def getIdentyIdp(self):
        # get IdP
        task2 = asyncio.run_coroutine_threadsafe(self.dbobjSaml.execute_statment("get_provider_byentityid(%s, '%s')" %
                    ('True', '{'+(self.issuer.text.strip())+'}')),  globalsObj.ioloop)
        idpEntityId = waitFuture(task2)

        if idpEntityId['error'] == 0 and idpEntityId['result'] is not None:
            idp_metadata = idpEntityId['result'][0]['xml']
            idp = idpEntityId['result'][0]['cod_provider']
            return (idp_metadata, idp)

        elif idpEntityId['error'] == 0 and idpEntityId['result'] is None:
            response_obj = ResponseObj(httpcode=404)
            response_obj.setError('easyspid103')
            raise goExit(response_obj, 'exit by getIdentyIdp')

        elif idpEntityId['error'] > 0:
            response_obj = ResponseObj(httpcode=500, debugMessage=idpEntityId['result'])
            response_obj.setError("easyspid105")
            raise goExit(response_obj, 'exit by getIdentyIdp')

    @commonlib.inner_log
    def chkExistsReq(self, checkInResponseTo):
        # try to get sp searching a corresponding request and raise error if checkInResponseTo is True
        inResponseChk = waitFuture(asyncio.run_coroutine_threadsafe(
            self.dbobjSaml.execute_statment("chk_idAssertion('%s')" %
            self.inResponseTo), globalsObj.ioloop))

        if inResponseChk['error'] == 0 and inResponseChk['result'] is not None:
            return inResponseChk['result'][0]['cod_sp']

        elif checkInResponseTo and inResponseChk['error'] == 0 and inResponseChk['result'] == None:
            response_obj = ResponseObj(httpcode=404, ID =self.ResponseID)
            response_obj.setError('easyspid120')
            response_obj.setResult(response = str(self.response, 'utf-8'))
            raise goExit(response_obj, 'exit by chkExistsReq')

        elif not checkInResponseTo and inResponseChk['error'] == 0 and inResponseChk['result'] == None:
            response_obj = ResponseObj(httpcode=404, ID =self.ResponseID)
            response_obj.setError('easyspid120')
            response_obj.setResult(response = str(self.response, 'utf-8'))
            return None

        elif inResponseChk['error'] > 0:
            response_obj = ResponseObj(httpcode=500)
            response_obj.setError('easyspid105')
            response_obj.setResult(inResponseChk['result'])
            raise goExit(response_obj, 'exit by chkExistsReq')

    @commonlib.inner_log
    def getSpByAudience(self):

        task3 = asyncio.run_coroutine_threadsafe(self.dbobjSaml.execute_statment("get_provider_byentityid(%s, '%s')" %
                    ('True', '{'+(self.audience.text.strip())+'}')),  globalsObj.ioloop)
        audienceChk = waitFuture(task3)

        if audienceChk['error'] == 0 and audienceChk['result'] is not None:
            return audienceChk['result'][0]['cod_provider']

        elif audienceChk['error'] == 0 and audienceChk['result'] is None:
            response_obj = ResponseObj(httpcode=404)
            response_obj.setError('easyspid115')
            raise goExit(response_obj, 'exit by getSpByAudience')

        elif audienceChk['error'] > 0:
            response_obj = ResponseObj(httpcode=500)
            response_obj.setError('easyspid105')
            response_obj.setResult(audienceChk['result'])
            raise goExit(response_obj, 'exit by getSpByAudience')



