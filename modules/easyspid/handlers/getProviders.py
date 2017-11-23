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

class getProvidershandler(easyspidHandler):

    def __init__(self, *args, **kwds):
        super().__init__(*args, **kwds)

    #get
    async def get(self, active = True):
        x_real_ip = self.request.headers.get("X-Real-IP")
        #self.remote_ip = x_real_ip or self.request.remote_ip
        #self.set_header('Content-Type', 'application/json; charset=UTF-8')
        self.set_default_headers()

        response_obj = await self.getProviders(active)
        asyncio.ensure_future(self.writeLog(response_obj), loop = globalsObj.ioloop)
        super().writeResponse(response_obj)


    async def getProviders(self, active = True):
        try:
            sp_metadata  = await self.dbobjSaml.execute_statment("get_providers(%s)" % active)

            if sp_metadata['error'] == 0 and sp_metadata['result'] is not None:
                tmp = list()
                for index, record in enumerate(sp_metadata['result']):
                    tmp.append({'code': record['cod_provider'],
                                  'name': record['name'],
                                  'type': record['type'],
                                  'description': record['description']})

                response_obj = ResponseObj(httpcode=200)
                response_obj.setError('200')
                response_obj.setResult(providers = tmp)

            elif sp_metadata['error'] == 0 and sp_metadata['result'] is None:
                response_obj = ResponseObj(httpcode=404)
                response_obj.setError('easyspid101')

            elif sp_metadata['error'] > 0:
                response_obj = ResponseObj(httpcode=500, debugMessage=sp_metadata['result'])
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
            logging.getLogger(__name__).warning('easyspid/getProviders handler executed')

        return response_obj


