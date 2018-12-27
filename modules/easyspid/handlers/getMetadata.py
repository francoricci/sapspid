from response import ResponseObj
import tornado.web
import tornado.gen
import tornado.ioloop
import tornado.concurrent
import tornado.httpclient
import logging
import asyncio
from easyspid.handlers.easyspidhandler import easyspidHandler
from easyspid.handlers.buildMetadata import buildMetadatahandler
import globalsObj
import easyspid.lib.easyspid
import commonlib

class getMetadatahandler(buildMetadatahandler):

    def __init__(self, *args, **kwds):
        super().__init__(*args, **kwds)

    #get
    async def get(self, sp):
        x_real_ip = self.request.headers.get(globalsObj.easyspid_originIP_header)
        self.remote_ip = x_real_ip or self.request.remote_ip
        self.set_header('Content-Type', 'application/json; charset=UTF-8')
        self.set_default_headers()

        try:
            ##ceck provider type
            provider_type = await self.dbobjSaml.execute_query(self.dbobjSaml.query['get_provider']['sql'], sp)

            if provider_type['error'] == 0 and provider_type['result'][0]['type'] == 'sp':
                chk_metadata = await self.dbobjSaml.execute_query(self.dbobjSaml.query['chk_metadata_validity']['sql'], sp)

                if chk_metadata['error'] == 0 and chk_metadata['result'][0]['chk'] == 0:
                    sp_settings = await easyspid.lib.easyspid.spSettings(sp, close = True)
                    await asyncio.get_event_loop().run_in_executor(self.executor, self.buildMetadata, sp_settings)
                    #self.buildMetadata(sp_settings, dbSave = True)

            sp_metadata  = await self.dbobjSaml.execute_statment("get_prvd_metadta('%s')" % sp)

        except tornado.web.MissingArgumentError as error:
            response_obj = ResponseObj(debugMessage=error.log_message, httpcode=error.status_code,
                                       devMessage=error.log_message)
            response_obj.setError(str(error.status_code))
            logging.getLogger(type(self).__module__+"."+type(self).__qualname__).error('%s'% error,exc_info=True)
            return response_obj

        except Exception as inst:
            response_obj = ResponseObj(httpcode=500)
            response_obj.setError('500')
            logging.getLogger(type(self).__module__+"."+type(self).__qualname__).error('Exception',exc_info=True)
            return response_obj

        response_obj = self.getMetadata(sp_metadata)
        asyncio.ensure_future(self.writeLog(response_obj), loop = globalsObj.ioloop)
        super().writeResponse(response_obj)

    @staticmethod
    @commonlib.inner_log
    def getMetadata(sp_metadata):

        if sp_metadata['error'] == 0 and sp_metadata['result'] is not None:
            # genera risposta tutto ok
            metadata = sp_metadata['result'][0]['xml']
            public_key = sp_metadata['result'][0]['public_key']
            fingerprint = sp_metadata['result'][0]['fingerprint']
            fingerprintalg = sp_metadata['result'][0]['fingerprintalg']
            #private_key = sp_metadata['result'][0]['private_key']

            response_obj = ResponseObj(httpcode=200)
            response_obj.setError('200')
            #response_obj.setResult(metadata = metadata, x509cert = public_key, key = private_key,
            #            x509certFingerPrint = fingerprint, fingerPrintAlg = fingerprintalg)
            response_obj.setResult(metadata = metadata, x509cert = public_key,
                        x509certFingerPrint = fingerprint, fingerPrintAlg = fingerprintalg)

        elif sp_metadata['error'] == 0 and sp_metadata['result'] is None:
            response_obj = ResponseObj(httpcode=404)
            response_obj.setError('easyspid101')

        elif sp_metadata['error'] > 0:
            response_obj = ResponseObj(httpcode=500, debugMessage=sp_metadata['result'])
            response_obj.setError("easyspid105")


        return response_obj


