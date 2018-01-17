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
from easyspid.lib.utils import Saml2_Settings, waitFuture

class buildMetadatahandler(easyspidHandler):

    def __init__(self, *args, **kwds):
        super().__init__(*args, **kwds)

    #get
    async def get(self, sp):
        x_real_ip = self.request.headers.get("X-Real-IP")
        self.remote_ip = x_real_ip or self.request.remote_ip
        self.set_header('Content-Type', 'application/json; charset=UTF-8')
        self.set_default_headers()

        #settings
        sp_settings = await easyspid.lib.easyspid.spSettings(sp, close = True)
        response_obj = await asyncio.get_event_loop().run_in_executor(self.executor, self.buildMetadata, sp_settings)

        asyncio.ensure_future(self.writeLog(response_obj), loop = globalsObj.ioloop)
        super().writeResponse(response_obj)

    @staticmethod
    def makeMetadata(sp_settings):

        if sp_settings['error'] == 0 and sp_settings['result'] is not None:
            spSettings = Saml2_Settings(sp_settings['result'])
            metadata = spSettings.get_sp_metadata()
            metadata = str(metadata,'utf-8')

            response_obj = ResponseObj(httpcode=200)
            response_obj.setError('200')
            response_obj.setResult(metadata = metadata)

        elif sp_settings['error'] == 0 and sp_settings['result'] is None:
            response_obj = ResponseObj(httpcode=404)
            response_obj.setError('easyspid101')

        elif sp_settings['error'] > 0:
            response_obj = ResponseObj(httpcode=500, debugMessage=sp_settings['result'])
            response_obj.setError("easyspid105")

        return response_obj

    def buildMetadata(self, sp_settings, dbSave = True):

        try:
            makeMetadata = self.makeMetadata(sp_settings)

            if makeMetadata.error.code == '200':
                metadata = makeMetadata.result.metadata
                sp = sp_settings['result']['sp']['cod_sp']

                ## insert into DB
                if dbSave:
                    task = asyncio.run_coroutine_threadsafe(self.dbobjSaml.execute_statment("write_assertion('%s', '%s', %s, '%s')" %
                        (metadata.replace("'", "''"), sp, 'NULL', self.remote_ip)), globalsObj.ioloop)
                    wrtMetada = waitFuture(task)

                    #task1 = asyncio.run_coroutine_threadsafe(self.dbobjSaml.execute_query(self.dbobjSaml.query['chk_metadata_validity']['sql'],
                    #                                                                      sp), globalsObj.ioloop)
                    #chk_metadata = waitFuture(task1)

                    if wrtMetada['error'] == 0:

                        task = asyncio.run_coroutine_threadsafe(self.dbobjJwt.execute_statment("get_token_by_cod('%s')" %
                            (wrtMetada['result'][0]['cod_token'])), globalsObj.ioloop)
                        jwt = waitFuture(task)

                        response_obj = ResponseObj(httpcode=200, ID = wrtMetada['result'][0]['ID_assertion'])
                        response_obj.setError('200')
                        response_obj.setResult(metadata = metadata, jwt=jwt['result'][0]['token'],
                                               idassertion=wrtMetada['result'][0]['ID_assertion'])

                        # insert metadata in saml.metadata table
                        task = asyncio.run_coroutine_threadsafe(self.dbobjSaml.execute_query(self.dbobjSaml.query['insert_metadata']['sql'],
                                sp+"_metadata", metadata, sp), globalsObj.ioloop)
                        insert_metadata = waitFuture(task)

                    else:
                        response_obj = ResponseObj(httpcode=500, debugMessage=wrtMetada['result'])
                        response_obj.setError("easyspid105")
                        logging.getLogger(__name__).error('Exception',exc_info=True)
                else:
                    response_obj = ResponseObj(httpcode=200)
                    response_obj.setError('200')
                    response_obj.setResult(metadata = metadata, jwt="")

            else:

                response_obj = makeMetadata

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
            logging.getLogger(__name__).warning('easyspid/makeMetadata handler executed')

        return response_obj

