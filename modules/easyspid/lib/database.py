import asyncpg
import jsonpickle

class Database(object):
    
    def __init__(self, **kwds):

        # define query to prepare
        self.stmts = dict()
        self.query = dict()
        self.stmts['get_prvd_metadta'] = {'sql':"PREPARE get_prvd_metadta (text) AS " \
                    "SELECT t1.*, t2.public_key, t2.private_key, t2.fingerprint, t2.fingerprintalg FROM saml.metadata as t1 " \
                    "LEFT JOIN saml.signatures as t2 on t2.cod_provider = t1.cod_provider " \
                    "where t1.cod_provider = $1 and t1.active = TRUE LIMIT 1"}

        self.stmts['get_sp_settings'] = {'sql':"PREPARE get_sp_settings (text) AS " \
                    "SELECT t1.*, t2.public_key, t2.private_key, t2.fingerprint, t2.fingerprintalg FROM saml.settings as t1 " \
                    "LEFT JOIN saml.signatures as t2 on t2.cod_provider = t1.cod_provider " \
                    "where t1.cod_provider = $1 and t1.active = TRUE LIMIT 1"}

        self.stmts['get_providers'] = {'sql':"PREPARE get_providers (bool) AS " \
                    "SELECT t1.* FROM saml.providers as t1 where t1.active = $1 ORDER BY name ASC"}

        self.stmts['get_provider_byentityid'] = {'sql':"PREPARE get_provider_byentityid (bool, text) AS " \
                "SELECT t1.* FROM saml.metadata as t1 where t1.active = $1 " \
                "and cast(xpath('/md1:EntityDescriptor/@entityID', \"xml\", ARRAY[ARRAY['md1', 'urn:oasis:names:tc:SAML:2.0:metadata']]) as text) = $2" \
                "ORDER BY cod_provider ASC"}

        self.stmts['write_assertion'] = {'sql':"PREPARE write_assertion (xml, text, text, inet) AS " \
                        "INSERT INTO saml.assertions (assertion, cod_sp, cod_idp, client) VALUES ($1, $2, $3, $4) " \
                        "RETURNING cod_token, \"ID_assertion\""}

        self.stmts['get_service'] = {'sql':"PREPARE get_service (bool, text, text) AS " \
                        "SELECT t1.* FROM saml.services as t1 where t1.active = $1 and t1.relay_state = $2 "
                        "and t1.cod_provider = $3"}

        self.stmts['get_idAssertion'] = {'sql':"PREPARE get_idAssertion (text) AS " \
                        "SELECT t1.* FROM saml.view_assertions as t1 where t1.\"ID_assertion\" = $1"}

        self.stmts['chk_idAssertion'] = {'sql':"PREPARE chk_idAssertion (text) AS " \
                        "SELECT t1.* FROM saml.view_assertions as t1 where t1.\"ID_assertion\" = $1"}

        self.stmts['log_request'] = {'sql':"PREPARE log_request (text, text, text, inet) AS " \
                        "INSERT INTO log.requests (http_verb, url, request, client) VALUES ($1, $2, $3, $4)"}

        self.stmts['log_response'] = {'sql':"PREPARE log_response (text, text, text, inet) AS " \
                        "INSERT INTO log.responses (http_code, url_origin, response, client) VALUES ($1, $2, $3, $4)"}

        self.stmts['get_signature'] = {'sql':"PREPARE get_signature (text) AS " \
                        "SELECT * FROM saml.signatures WHERE cod_provider = $1"}

        self.query['insert_metadata'] = {'sql': "INSERT INTO saml.metadata as t1 (cod_metadata, xml, active, cod_provider) " \
                    "VALUES ($1, $2, True, $3) ON CONFLICT (cod_metadata) DO UPDATE SET xml = $2 WHERE t1.cod_provider = $3"}

        self.query['chk_metadata_validity'] = {'sql': "SELECT COUNT(*) as chk FROM saml.metadata as t1 " \
                    "LEFT JOIN saml.settings as t2 on t1.cod_provider = t2.cod_provider " \
                    "LEFT JOIN saml.signatures as t3 on t1.cod_provider = t3.cod_provider " \
                    "WHERE (t1.date > t2.date AND t1.date > t3.date) and t1.cod_provider = $1"}

        self.query['get_provider'] = {'sql': "SELECT * FROM saml.providers as t1 WHERE t1.cod_provider = $1"}

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

    async def execute_query(self, sql, *args, release =True):
        result = None
        output = {'error':1, 'result': result}

        conn = await self.acquire()
        try:
            record = await conn.fetch(sql, *args)
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
                                     max_size = settings['max_conn'], init = init)
    return pool