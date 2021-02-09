stmts = dict()
stmts['get_token_by_cod'] = {'sql':"PREPARE get_token_by_cod (text) AS " \
            "SELECT * FROM jwt.token WHERE cod_token LIKE $1"}

stmts['create_token_by_type'] = {'sql':"PREPARE create_token_by_type (text) AS " \
                "SELECT lib.create_token_byType($1) as cod_token"}

stmts['verify_token'] = {'sql':"PREPARE verify_token (text) AS " \
                "SELECT lib.verify_token_bycod((SELECT t1.cod_token FROM jwt.token as t1"
                " WHERE t1.token = $1))"}

stmts['verify_saml_bytoken'] = {'sql':"PREPARE verify_saml_bytoken (text) AS " \
                "SELECT lib.verify_saml_by_cod_token((SELECT t1.cod_token FROM jwt.token as t1"
                " WHERE t1.token = $1), true) as verify_saml_by_cod_token"}

stmts['log_request'] = {'sql':"PREPARE log_request (text, text, jsonb, inet) AS " \
                "INSERT INTO log.requests (http_verb, url, request, client) VALUES ($1, $2, $3, $4)"}

stmts['log_response'] = {'sql':"PREPARE log_response (text, text, jsonb, inet) AS " \
                "INSERT INTO log.responses (http_code, url_origin, response, client) VALUES ($1, $2, $3, $4)"}