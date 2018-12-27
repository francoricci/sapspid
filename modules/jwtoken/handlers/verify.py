from response import ResponseObj
from request import RequestObjNew

import tornado.web
import tornado.gen
import tornado.ioloop
import tornado.concurrent
import logging
import commonlib
from jwtoken.handlers.jwtokenhandler import jwtokenHandler
import asyncio
import globalsObj

class verifyHandler(jwtokenHandler):

    def __init__(self, *args, **kwds):
        super().__init__(*args, **kwds)

    #get
    async def get(self):
        self.set_header('Content-Type', 'application/json; charset=UTF-8')
        self.set_default_headers()

        response_obj = await self.verify()
        asyncio.ensure_future(self.writeLog(response_obj), loop = globalsObj.ioloop)
        self.writeResponse(response_obj)

    #post
    async def post(self):
        self.set_header('Content-Type', 'application/json; charset=UTF-8')
        self.set_default_headers()

        response_obj = await self.verify()
        asyncio.ensure_future(self.writeLog(response_obj), loop = globalsObj.ioloop)
        self.writeResponse(response_obj)

    @commonlib.inner_log
    async def verify(self):
        try:
            if self.request.method == 'GET':
                token = super(self.__class__, self).get_argument('token')

            elif  self.request.method == 'POST':
                # leggi il json della richiesta
                temp = RequestObjNew(self.request.body)

                if temp.error["code"] == 2:
                    response_obj = ResponseObj(debugMessage=temp.error["message"], httpcode=400)
                    response_obj.setError('400')
                    logging.getLogger(type(self).__module__+"."+type(self).__qualname__).error('Validation error. Json input error')
                    return response_obj

                elif temp.error["code"] > 0:
                    raise tornado.web.HTTPError(httpcode=503, log_message=temp.error["message"])

                token = temp.request['token']

            verifica = await self.dbobjJwt.execute_statment("verify_token('%s')" % token)

            if verifica['error'] == 0:
                if verifica['result'][0]['verify_token_bycod'] == None:
                    response_obj = ResponseObj(httpcode=404)
                    response_obj.setError('jwtoken101')

                elif verifica['result'][0]['verify_token_bycod']['error'] == 0:
                    response_obj = ResponseObj(httpcode=200)
                    response_obj.setError('200')
                    response_obj.setResult(jose = verifica['result'][0]['verify_token_bycod']['message'])

                elif verifica['result'][0]['verify_token_bycod']['error'] > 0:
                    response_obj = ResponseObj(httpcode=401, devMessage=(verifica['result'][0]['verify_token_bycod']['message']))
                    response_obj.setError('jwtoken100')

            elif verifica['error'] > 0:
                response_obj = ResponseObj(debugMessage=verifica['result'], httpcode=500)
                response_obj.setError('jwtoken105')

        except tornado.web.MissingArgumentError as error:
            response_obj = ResponseObj(debugMessage=error.log_message, httpcode=error.status_code,
                                       devMessage=error.log_message)
            response_obj.setError(str(error.status_code))
            logging.getLogger(type(self).__module__+"."+type(self).__qualname__).error('%s'% error,exc_info=True)

        except Exception as inst:
            response_obj = ResponseObj(httpcode=500)
            response_obj.setError('500')
            logging.getLogger(type(self).__module__+"."+type(self).__qualname__).error('Exception',exc_info=True)

        if  self.request.method == 'POST':
            response_obj.setID(temp.id)

        return response_obj
