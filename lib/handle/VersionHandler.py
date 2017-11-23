import response
import asyncio
import globalsObj
import time

class GetVersion(response.RequestHandler):

    def write_error(self, status_code, **kwargs):
        super(self.__class__, self).write_error(status_code, errorcode = '3', **kwargs)

    async def get(self):
        self.set_header('Content-Type', 'application/json; charset=UTF-8')
        self.set_status(200)

        res = await globalsObj.ioloop.run_in_executor(self.executor, self.background_task)

        # to run hybrid tasks
        #res = await globalsObj.ioloop.run_in_executor(self.executor, self.block_task)

        self.write(res)
        self.finish()

    def background_task(self):
        getResponse = response.ResponseObj(httpcode=200)
        getResponse.setError('0')
        getResponse.setResult(ApiVersion = getResponse.apiVersion)
        return getResponse.jsonWrite()


    def block_task(self):
        # run corutine
        feature = asyncio.run_coroutine_threadsafe(self.corutine(), globalsObj.ioloop)

        # run corutine and wait
        #loop = asyncio.new_event_loop()
        #asyncio.set_event_loop(loop)
        #print(loop.run_until_complete(self.corutine()))

        # run block task
        time.sleep(5)
        print("blocking ....")

        getResponse = response.ResponseObj(httpcode=200)
        getResponse.setError('0')
        getResponse.setResult(ApiVersion = getResponse.apiVersion)
        return getResponse.jsonWrite()

    async def corutine(self):

        print("corutine ....")
        await asyncio.sleep(5)
        return 'OK'

