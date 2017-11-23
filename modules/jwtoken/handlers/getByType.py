from response import ResponseObj

import tornado.web
import tornado.gen
import tornado.ioloop
import tornado.concurrent
import logging
from lib.customException import ApplicationException
import globalsObj
import re
from jwtoken.handlers.jwtokenhandler import jwtokenHandler
import asyncio

class getByTypeHandler(jwtokenHandler):

    def __init__(self, *args, **kwds):
        super().__init__(*args, **kwds)

    #get
    async def get(self):
        self.set_header('Content-Type', 'application/json; charset=UTF-8')
        self.set_default_headers()

        response_obj = await self.getByType()
        asyncio.ensure_future(self.writeLog(response_obj), loop = globalsObj.ioloop)
        self.writeResponse(response_obj)

    async def getByType(self):
        try:
            jwtCode = super(self.__class__, self).get_argument('type')

            newcod_cod_token = await self.dbobjJwt.execute_statment("create_token_by_type('%s')" % jwtCode)
            newcod_token = await self.dbobjJwt.execute_statment("get_token_by_cod('%s')" % newcod_cod_token['result'][0]['cod_token'])

            if newcod_token['error'] == 0 and newcod_token['result'] is not None:
                # genera risposta tutto ok
                response_obj = ResponseObj(httpcode=200)
                response_obj.setError('200')
                response_obj.setResult(token = newcod_token['result'][0]['token'])

            elif newcod_token['error'] == 0 and newcod_token['result'] is None:
                response_obj = ResponseObj(httpcode=404)
                response_obj.setError('jwtoken102')

            elif newcod_token['error'] > 0:
                response_obj = ResponseObj(debugMessage=("PostgreSQL error code: %s" % newcod_token['result'].sqlstate),
                        httpcode=500,
                        devMessage=("PostgreSQL error message: %s" % newcod_token['result'].message))
                response_obj.setError('jwtoken105')

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
            logging.getLogger(__name__).warning('jwt/getByType handler executed')

        return response_obj
