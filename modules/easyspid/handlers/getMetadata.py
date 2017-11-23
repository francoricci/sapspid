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

class getMetadatahandler(easyspidHandler):

    def __init__(self, *args, **kwds):
        super().__init__(*args, **kwds)

    #get
    async def get(self, sp):
        self.set_header('Content-Type', 'application/json; charset=UTF-8')
        self.set_default_headers()

        try:
            sp_metadata  = await self.dbobjSaml.execute_statment("get_prvd_metadta('%s')" % sp)

        except tornado.web.MissingArgumentError as error:
            response_obj = ResponseObj(debugMessage=error.log_message, httpcode=error.status_code,
                                       devMessage=error.log_message)
            response_obj.setError(str(error.status_code))
            logging.getLogger(__name__).error('%s'% error,exc_info=True)
            return response_obj

        except ApplicationException as inst:
            response_obj = ResponseObj(httpcode=500)
            response_obj.setError(inst.code)
            logging.getLogger(__name__).error('Exception',exc_info=True)
            return response_obj

        except Exception as inst:
            response_obj = ResponseObj(httpcode=500)
            response_obj.setError('500')
            logging.getLogger(__name__).error('Exception',exc_info=True)
            return response_obj

        finally:
            logging.getLogger(__name__).warning('easyspid/getMetadata handler executed')


        response_obj = self.getMetadata(sp_metadata)
        asyncio.ensure_future(self.writeLog(response_obj), loop = globalsObj.ioloop)
        super().writeResponse(response_obj)

    @staticmethod
    def getMetadata(sp_metadata):

        if sp_metadata['error'] == 0 and sp_metadata['result'] is not None:
            # genera risposta tutto ok
            metadata = sp_metadata['result'][0]['xml']
            public_key = sp_metadata['result'][0]['public_key']
            fingerprint = sp_metadata['result'][0]['fingerprint']
            fingerprintalg = sp_metadata['result'][0]['fingerprintalg']
            private_key = sp_metadata['result'][0]['private_key']

            response_obj = ResponseObj(httpcode=200)
            response_obj.setError('200')
            response_obj.setResult(metadata = metadata, x509cert = public_key, key = private_key,
                        x509certFingerPrint = fingerprint, fingerPrintAlg = fingerprintalg)

        elif sp_metadata['error'] == 0 and sp_metadata['result'] is None:
            response_obj = ResponseObj(httpcode=404)
            response_obj.setError('easyspid101')

        elif sp_metadata['error'] > 0:
            response_obj = ResponseObj(httpcode=500, debugMessage=sp_metadata['result'])
            response_obj.setError("easyspid105")


        return response_obj


