import response
import tornado.gen
import tornado.concurrent

class GetVersion(response.RequestHandler):

    def write_error(self, status_code, **kwargs):
        super(self.__class__, self).write_error(status_code, errorcode = '3', **kwargs)

    #@tornado.gen.coroutine
    async def get(self):
        self.set_header('Content-Type', 'application/json; charset=UTF-8')
        self.set_status(200)
        fut = self.executor.submit(self.background_task)
        res = await tornado.platform.asyncio.to_tornado_future(fut)
        #res = yield self.background_task()
        self.write(res)
        self.finish()


    #@tornado.concurrent.run_on_executor
    def background_task(self):
        getResponse = response.ResponseObj(httpcode=200)
        getResponse.setError('0')
        getResponse.setResult(ApiVersion = getResponse.apiVersion)
        return getResponse.jsonWrite()

