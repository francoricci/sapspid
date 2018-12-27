from response import ResponseObj
from request import RequestObjNew
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
from easyspid.lib.utils import Saml2_Settings
import commonlib

class verifyMetadatahandler(easyspidHandler):

    def __init__(self, *args, **kwds):
        super().__init__(*args, **kwds)

    #post
    async def post(self, sp):
        x_real_ip = self.request.headers.get(globalsObj.easyspid_originIP_header)
        self.remote_ip = x_real_ip or self.request.remote_ip
        self.set_header('Content-Type', 'application/json; charset=UTF-8')
        self.set_default_headers()

        #settings
        sp_settings = await easyspid.lib.easyspid.spSettings(sp, close = True)
        response_obj = await asyncio.get_event_loop().run_in_executor(self.executor, self.verifySpMetadata, sp_settings)

        asyncio.ensure_future(self.writeLog(response_obj), loop = globalsObj.ioloop)
        super().writeResponse(response_obj)

    @commonlib.inner_log
    def verifySpMetadata(self, sp_settings):
        try:

            temp = RequestObjNew(self.request.body)
            if temp.error["code"] == 2:
                response_obj = ResponseObj(debugMessage=temp.error["message"], httpcode=400)
                response_obj.setError('400')
                logging.getLogger(type(self).__module__+"."+type(self).__qualname__).error('Validation error. Json input error')
                return response_obj

            elif temp.error["code"] > 0:
                raise tornado.web.HTTPError(httpcode=503, log_message=temp.error["message"])

            metadata = temp.request['metadata']

            if sp_settings['error'] == 0 and sp_settings['result'] is not None:
                # genera risposta tutto ok

                spSettings = Saml2_Settings(sp_settings['result'])

                chk = spSettings.validate_metadata(metadata,
                        fingerprint = sp_settings['result']['sp']['x509cert_fingerprint'],
                        fingerprintalg = sp_settings['result']['sp']['x509cert_fingerprintalg'],
                        validatecert=False)

                if not chk['schemaValidate']:
                    response_obj = ResponseObj(httpcode=401)
                    response_obj.setError('easyspid104')
                    response_obj.setResult(metadataValidate = chk)

                elif not chk['signCheck']:
                    response_obj = ResponseObj(httpcode=401)
                    response_obj.setError('easyspid106')
                    response_obj.setResult(metadataValidate = chk)

                elif chk['schemaValidate'] and chk['signCheck']:
                    response_obj = ResponseObj(httpcode=200)
                    response_obj.setError('200')
                    response_obj.setResult(metadataValidate = chk)

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
            logging.getLogger(type(self).__module__+"."+type(self).__qualname__).error('%s'% error,exc_info=True)

        except Exception as inst:
            response_obj = ResponseObj(httpcode=500)
            response_obj.setError('500')
            logging.getLogger(type(self).__module__+"."+type(self).__qualname__).error('Exception',exc_info=True)

        response_obj.setID(temp.id)
        return response_obj


