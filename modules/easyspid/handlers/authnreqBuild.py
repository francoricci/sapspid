from response import ResponseObj
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
from easyspid.lib.utils import Saml2_Settings, waitFuture, AddSign
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from easyspid.handlers.buildMetadata import buildMetadatahandler
import xml.etree.ElementTree
from easyspid.lib.authn_request import Saml2_Authn_Request


class authnreqBuildhandler(easyspidHandler):

    def __init__(self, *args, **kwds):
        super().__init__(*args, **kwds)

    #get
    async def get(self, sp):
        x_real_ip = self.request.headers.get("X-Real-IP")
        self.remote_ip = x_real_ip or self.request.remote_ip
        self.set_header('Content-Type', 'application/json; charset=UTF-8')
        self.set_default_headers()
        bindingMap = {'redirect':OneLogin_Saml2_Constants.BINDING_HTTP_REDIRECT,
                          'post': OneLogin_Saml2_Constants.BINDING_HTTP_POST}

        idp = self.get_argument('idp')
        attributeIndex = self.get_argument('attrindex')
        binding = self.get_argument('binding')
        sp_metadata = None

        #settings
        task1 = asyncio.ensure_future(easyspid.lib.easyspid.spSettings(sp, idp, binding=bindingMap[binding], close = True),
                loop = globalsObj.ioloop)
        #sp_settings = await easyspid.lib.easyspid.spSettings(sp, idp, binding=bindingMap[binding], close = True)
        chk_metadata = await self.dbobjSaml.execute_query(self.dbobjSaml.query['chk_metadata_validity']['sql'], sp)

        if chk_metadata['error'] == 0 and chk_metadata['result'][0]['chk'] > 0:
            sp_metadata_result  = await self.dbobjSaml.execute_statment("get_prvd_metadta('%s')" % sp)

            if sp_metadata_result['error'] == 0 and sp_metadata_result['result'] is not None:
                sp_metadata = sp_metadata_result['result'][0]['xml']

        sp_settings = await task1

        #response_obj = await asyncio.get_event_loop().run_in_executor(self.executor, self.buildAthnReq, sp_settings, attributeIndex, binding)
        response_obj = await asyncio.get_event_loop().run_in_executor(self.executor, self.buildAthnReq, sp_settings, attributeIndex, sp_metadata)
        asyncio.ensure_future(self.writeLog(response_obj), loop = globalsObj.ioloop)
        super().writeResponse(response_obj)


    def buildAthnReq(self, sp_settings, attributeIndex, sp_metadata = None, signed = True):

        try:
            if sp_settings['error'] == 0 and sp_settings['result'] is not None:
                sp = sp_settings['result']['sp']['cod_sp']
                idp = sp_settings['result']['idp']['cod_idp']

                # get sp metadata to read attributeIndex location.
                if sp_metadata is None:
                    sp_metadata = buildMetadatahandler.makeMetadata(sp_settings).result.metadata

                ns = {'md0': OneLogin_Saml2_Constants.NS_MD, 'md1': OneLogin_Saml2_Constants.NS_SAML}
                parsedMetadata = xml.etree.ElementTree.fromstring(sp_metadata)
                attributeConsumingService = parsedMetadata.find("md0:SPSSODescriptor/md0:AssertionConsumerService[@index='%s']" %
                                                                attributeIndex, ns)
                if attributeConsumingService == None:
                    response_obj = ResponseObj(httpcode=404)
                    response_obj.setError('easyspid102')
                    return response_obj

                spSettings = Saml2_Settings(sp_settings['result'])

                key = spSettings.get_sp_key()
                cert = spSettings.get_sp_cert()
                sign_alg = (spSettings.get_security_data())['signatureAlgorithm']
                digest = (spSettings.get_security_data())['digestAlgorithm']

                # build auth request
                authn_request = Saml2_Authn_Request(spSettings, force_authn=True, is_passive=False, set_nameid_policy=True)
                authn_request_xml = authn_request.get_xml()

                ## inserisci attribute index
                ns = {'md0': OneLogin_Saml2_Constants.NS_MD, 'md1': OneLogin_Saml2_Constants.NS_SAML}
                xml.etree.ElementTree.register_namespace('md0', OneLogin_Saml2_Constants.NS_MD)
                xml.etree.ElementTree.register_namespace('md1', OneLogin_Saml2_Constants.NS_SAML)

                parsedMetadata = xml.etree.ElementTree.fromstring(authn_request_xml)
                parsedMetadata.attrib['AttributeConsumingServiceIndex'] = attributeIndex
                parsedMetadata.attrib['AssertionConsumerServiceURL'] = attributeConsumingService.attrib['Location']

                issuer = parsedMetadata.find("md1:Issuer", ns)
                issuer.set("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:entity")
                issuer.set("NameQualifier", (spSettings.get_sp_data())['entityId'])

                ## inserisci attributi del nodo isuuer
                authn_request_xml = xml.etree.ElementTree.tostring(parsedMetadata, encoding="unicode")
                if signed:
                    #authn_request_signed = OneLogin_Saml2_Utils.add_sign(authn_request_xml, key, cert, debug=False,
                    #                    sign_algorithm=sign_alg, digest_algorithm=digest)
                    authn_request_signed = AddSign(authn_request_xml, key, cert, False, sign_alg, digest)
                    authn_request_signed = str(authn_request_signed,'utf-8')
                else:
                    authn_request_signed = authn_request_xml

                ## insert into DB
                task = asyncio.run_coroutine_threadsafe(self.dbobjSaml.execute_statment("write_assertion('%s', '%s', '%s', '%s')" %
                        (authn_request_signed.replace("'", "''"), sp, idp, self.remote_ip)), globalsObj.ioloop)
                #assert not task.done()
                #wrtAuthn = task.result()
                wrtAuthn = waitFuture(task)

                if wrtAuthn['error'] == 0:
                    task = asyncio.run_coroutine_threadsafe(self.dbobjJwt.execute_statment("get_token_by_cod('%s')" %
                            (wrtAuthn['result'][0]['cod_token'])), globalsObj.ioloop)
                    #assert not task.done()
                    #jwt = task.result()
                    jwt = waitFuture(task)

                    response_obj = ResponseObj(httpcode=200, ID = wrtAuthn['result'][0]['ID_assertion'])
                    response_obj.setError('200')
                    response_obj.setResult(authnrequest = authn_request_signed, jwt=jwt['result'][0]['token'],
                                           idassertion=wrtAuthn['result'][0]['ID_assertion'])
                else:
                    response_obj = ResponseObj(httpcode=500, debugMessage=wrtAuthn['result'])
                    response_obj.setError("easyspid105")
                    logging.getLogger(__name__).error('Exception',exc_info=True)

            elif sp_settings['error'] == 0 and sp_settings['result'] == None:
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
            logging.getLogger(__name__).error('Exception',exc_info=True)

        except Exception as inst:
            response_obj = ResponseObj(httpcode=500)
            response_obj.setError('500')
            logging.getLogger(__name__).error('Exception',exc_info=True)

        finally:
            logging.getLogger(__name__).warning('easyspid/buildAthnReq handler executed')

        return response_obj