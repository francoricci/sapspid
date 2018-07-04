import asyncpg
import jsonpickle

class Database(object):
    
    def __init__(self, **kwds):

        # define query to prepare
        self.stmts = dict()
        self.stmts['get_token_by_cod'] = {'sql':"PREPARE get_token_by_cod (text) AS " \
                    "SELECT * FROM jwt.token WHERE cod_token LIKE $1"}

        self.stmts['create_token_by_type'] = {'sql':"PREPARE create_token_by_type (text) AS " \
                        "SELECT lib.create_token_byType($1) as cod_token"}

        self.stmts['verify_token'] = {'sql':"PREPARE verify_token (text) AS " \
                        "SELECT lib.verify_token_bycod((SELECT t1.cod_token FROM jwt.token as t1"
                        " WHERE t1.token = $1))"}

        self.stmts['log_request'] = {'sql':"PREPARE log_request (text, text, jsonb, inet) AS " \
                        "INSERT INTO log.requests (http_verb, url, request, client) VALUES ($1, $2, $3, $4)"}

        self.stmts['log_response'] = {'sql':"PREPARE log_response (text, text, jsonb, inet) AS " \
                        "INSERT INTO log.responses (http_code, url_origin, response, client) VALUES ($1, $2, $3, $4)"}

    def set_pool(self, pool):
        self.pool1 = pool

    async def acquire(self):
        return await self.pool1.acquire()

    async def release(self, conn):
        return await self.pool1.release(conn)

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

    async def execute_statment(self, statment, release =True):
        result = None
        output = {'error':1, 'result': result}

        conn = await self.acquire()
        try:
            record = await conn.fetch("EXECUTE "+ statment)
            tmp = list()

            if len(record) > 0:
                for row in iter(record):
                    tmp.append(dict(row))
                output = {'error':0, 'result': tmp}
            else:
                output = {'error':0, 'result': None}

        except asyncpg.PostgresError as error:
            output = {'error':1, 'result': error}

        finally:
            if release:
                await self.release(conn)
            else:
                pass

            return output

    async def execute_query(self, sql, sqlargs, release =True):
        result = None
        output = {'error':1, 'result': result}

        conn = await self.acquire()
        try:
            record = await conn.fetch(sql, sqlargs)
            tmp = list()

            if len(record) > 0:
                for row in iter(record):
                    tmp.append(dict(row))
                output = {'error':0, 'result': tmp}
            else:
                output = {'error':0, 'result': None}

        except asyncpg.PostgresError as error:
            output = {'error':1, 'result':error.message}

        finally:
            if release:
                await self.release(conn)
            else:
                pass

            return output

async def init_pool(settings, init):

    pool = await asyncpg.create_pool(dsn = settings['dsn'], min_size = settings['min_conn'],
                                     max_size = settings['max_conn'], init = init, ssl=False)
    return pool
        