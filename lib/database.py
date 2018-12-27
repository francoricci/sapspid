import asyncpg
import jsonpickle
import inspect
import logging

class Database(object):

    def __init__(self, dsn, **kwds):

        self.stmts = dict()
        self.query = dict()
        self.dsn = dsn

    def set_pool(self, pool):
        self.pool = pool

    async def acquire(self):
        return await self.pool.acquire()

    async def release(self, conn):
        return await self.pool.release(conn)

    async def prepare_statements(self, conn):

        await conn.set_type_codec(
             'json', encoder=self._encoder, decoder=self._decoder,
             schema='pg_catalog')

        await conn.set_type_codec(
             'jsonb', encoder=self._encoder, decoder=self._decoder,
             schema='pg_catalog')

        for key, value in self.stmts.items():
            await conn.execute(value['sql'])

    def _encoder(self, value):
            return jsonpickle.encode(value, unpicklable=False)

    def _decoder(self, value):
        return jsonpickle.decode(value)

    async def execute_statment(self, statment, application_name="anonymous", release =True):
        result = None
        output = {'error':1, 'result': result}

        conn = await self.acquire()
        tr = conn.transaction()
        await tr.start()
        await conn.execute("SET application_name to '%s'" % set_application_name(application_name))

        try:
            record = await conn.fetch("EXECUTE "+ statment)
            tmp = list()

            if len(record) > 0:
                for row in iter(record):
                    tmp.append(dict(row))
                output = {'error':0, 'result': tmp}
            else:
                output = {'error':0, 'result': None}

            await tr.commit()

        except Exception as error:
            message =  self.print_asyncpg_error(error)
            await tr.rollback()
            output = {'error':1, 'result':message}

        finally:
            if release:
                await self.release(conn)
            else:
                pass

            return output

    async def execute_query(self, sql, *sqlargs, application_name="anonymous", release =True):
        result = None
        output = {'error':1, 'result': result}

        conn = await self.acquire()
        tr = conn.transaction()
        await tr.start()
        await conn.execute("SET application_name to '%s'" % set_application_name(application_name))

        try:
            record = await conn.fetch(sql, *sqlargs)
            tmp = list()

            if len(record) > 0:
                for row in iter(record):
                    tmp.append(dict(row))
                output = {'error':0, 'result': tmp}
            else:
                output = {'error':0, 'result': None}

            await tr.commit()

        except Exception as error:
            message = self.print_asyncpg_error(error)
            await tr.rollback()
            output = {'error':1, 'result':message}

        finally:
            if release:
                await self.release(conn)
            else:
                pass

            return output

    async def init_pool(self, settings, init):

        if 'max_queries' not in settings:
            settings['max_queries'] = 50000

        if 'max_inactive_connection_lifetime' not in settings:
            settings['max_inactive_connection_lifetime'] = 300.0

        if 'min_conn' not in settings:
            settings['min_conn'] = 1

        if 'max_conn' not in settings:
            settings['max_conn'] = 2
        try:
            pool = await asyncpg.create_pool(dsn = self.dsn,
                        min_size = settings['min_conn'],max_size = settings['max_conn'],
                        max_queries = settings['max_queries'], max_inactive_connection_lifetime = settings['max_conn'],
                        init = init)

            self.set_pool(pool)

        except Exception as error:
            self.print_asyncpg_error(error)
            quit()

        return pool

    async def init_connection(self):
        try:
            self.conn = await asyncpg.connect(dsn = self.dsn, ssl=False)

        except Exception as error:
            self.print_asyncpg_error(error)
            quit()

        return self.conn

    def print_asyncpg_error(self, error):
        message = list()

        for i in inspect.getmembers(error):
            # Ignores anything starting with underscore
            # (that is, private and protected attributes)
            # Ignores methods
            if not i[0].startswith('_') and i[1] is not None and not inspect.ismethod(i[1]) and not inspect.isclass(i[1]):
                if isinstance(i[1], str) and i[1] != 'None' and i[1] != '<NULL>s':
                    message.append(i[0]+" = "+ i[1])

        message = ', '.join(message)
        logging.getLogger(__name__).error("DB error:%s" % (message))

        return message

def set_application_name(application_name):

    if application_name !=  "anonymous":
        return application_name

    else:
        return application_name + "@Tornado"