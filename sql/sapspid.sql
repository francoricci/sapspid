--
-- PostgreSQL database dump
--

-- Dumped from database version 9.6.2
-- Dumped by pg_dump version 9.6.3

-- Started on 2017-07-25 15:16:33 CEST

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET client_min_messages = warning;
SET row_security = off;

--
-- TOC entry 2829 (class 1262 OID 16395)
-- Name: easyspid; Type: DATABASE; Schema: -; Owner: easyspid
--

CREATE DATABASE easyspid WITH TEMPLATE = template0 ENCODING = 'UTF8' LC_COLLATE = 'C' LC_CTYPE = 'C';


ALTER DATABASE easyspid OWNER TO easyspid;

\connect easyspid

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET client_min_messages = warning;
SET row_security = off;

--
-- TOC entry 11 (class 2615 OID 16413)
-- Name: jwt; Type: SCHEMA; Schema: -; Owner: easyspid
--

CREATE SCHEMA jwt;


ALTER SCHEMA jwt OWNER TO easyspid;

--
-- TOC entry 10 (class 2615 OID 16412)
-- Name: lib; Type: SCHEMA; Schema: -; Owner: easyspid
--

CREATE SCHEMA lib;


ALTER SCHEMA lib OWNER TO easyspid;

--
-- TOC entry 13 (class 2615 OID 77206)
-- Name: log; Type: SCHEMA; Schema: -; Owner: easyspid
--

CREATE SCHEMA log;


ALTER SCHEMA log OWNER TO easyspid;

--
-- TOC entry 12 (class 2615 OID 33833)
-- Name: saml; Type: SCHEMA; Schema: -; Owner: easyspid
--

CREATE SCHEMA saml;


ALTER SCHEMA saml OWNER TO easyspid;

--
-- TOC entry 2 (class 3079 OID 12744)
-- Name: plpgsql; Type: EXTENSION; Schema: -; Owner: 
--

CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog;


--
-- TOC entry 2831 (class 0 OID 0)
-- Dependencies: 2
-- Name: EXTENSION plpgsql; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION plpgsql IS 'PL/pgSQL procedural language';


--
-- TOC entry 1 (class 3079 OID 16407)
-- Name: plpython3u; Type: EXTENSION; Schema: -; Owner: 
--

CREATE EXTENSION IF NOT EXISTS plpython3u WITH SCHEMA pg_catalog;


--
-- TOC entry 2832 (class 0 OID 0)
-- Dependencies: 1
-- Name: EXTENSION plpython3u; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION plpython3u IS 'PL/Python3U untrusted procedural language';


--
-- TOC entry 3 (class 3079 OID 16396)
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner: 
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;


--
-- TOC entry 2833 (class 0 OID 0)
-- Dependencies: 3
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';


SET search_path = jwt, pg_catalog;

--
-- TOC entry 247 (class 1255 OID 32770)
-- Name: header_validator(); Type: FUNCTION; Schema: jwt; Owner: easyspid
--

CREATE FUNCTION header_validator() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
  DECLARE
       json_valid text;
       json_schema jsonb;
    BEGIN
       SELECT t1.schema INTO json_schema FROM jwt.token_schemas as t1
       WHERE t1.cod_type = NEW.cod_type and t1.part = 'header';

       SELECT lib.jsonvalidate(NEW.header, json_schema) INTO json_valid;
       
       IF json_valid = '0' THEN
            RETURN NEW;
       END IF;
        RAISE EXCEPTION '%s', json_valid;
        RETURN NULL;
    END;
$$;


ALTER FUNCTION jwt.header_validator() OWNER TO easyspid;

--
-- TOC entry 248 (class 1255 OID 32771)
-- Name: payload_validator(); Type: FUNCTION; Schema: jwt; Owner: easyspid
--

CREATE FUNCTION payload_validator() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
  DECLARE
       json_valid text;
       json_schema jsonb;
    BEGIN
       SELECT t1.schema INTO json_schema FROM jwt.token_schemas as t1
       WHERE t1.cod_type = NEW.cod_type and t1.part = 'payload';

       SELECT lib.jsonvalidate(NEW.payload, json_schema) INTO json_valid;
       
       IF json_valid = '0' THEN
            RETURN NEW;
       END IF;
        RAISE EXCEPTION '%s', json_valid;
        RETURN NULL;
    END;
$$;


ALTER FUNCTION jwt.payload_validator() OWNER TO easyspid;

--
-- TOC entry 255 (class 1255 OID 33823)
-- Name: schemas_validator(); Type: FUNCTION; Schema: jwt; Owner: easyspid
--

CREATE FUNCTION schemas_validator() RETURNS trigger
    LANGUAGE plpgsql
    AS $$

  DECLARE
       json_valid_pl integer;
       json_valid_he integer;
       results integer;
    BEGIN
     SELECT SUM(lib.jsonvalidate(t1.payload, NEW.schema)::integer) INTO json_valid_pl 
     FROM jwt.token_payload as t1 WHERE NEW.cod_type = t1.cod_type AND NEW.part = 'payload';
     IF (json_valid_pl IS NULL OR json_valid_pl = 0) THEN
        results := json_valid_pl;
     ELSE
        RAISE EXCEPTION '%s', json_valid_he;
        RETURN NULL;
     END IF;
       
     SELECT SUM(lib.jsonvalidate(t1.header, NEW.schema)::integer) INTO json_valid_he 
     FROM jwt.token_signature as t1 WHERE NEW.cod_type = t1.cod_type and NEW.part = 'header';
     IF (json_valid_he IS NULL OR json_valid_he = 0) THEN
        results := json_valid_he;
     ELSE
        RAISE EXCEPTION '%s', json_valid_he;
        RETURN NULL;
     END IF;
     RETURN NULL;
    END;

$$;


ALTER FUNCTION jwt.schemas_validator() OWNER TO easyspid;

SET search_path = lib, pg_catalog;

--
-- TOC entry 253 (class 1255 OID 32949)
-- Name: config_token_bytype(character varying); Type: FUNCTION; Schema: lib; Owner: easyspid
--

CREATE FUNCTION config_token_bytype(incod_type character varying DEFAULT 'jwt1'::character varying) RETURNS character varying
    LANGUAGE plpgsql PARALLEL SAFE
    AS $$

  DECLARE
       newheader jsonb;
       newcod_token varchar;
       validity integer;
       newpaylod jsonb;
       newdate timestamp with time zone;
       newepoch double precision;
       new_token text;
  BEGIN
   SELECT CURRENT_TIMESTAMP(0) into newdate;
   SELECT extract(epoch from newdate at time zone 'UTC') into newepoch;
   select t1.header, t1.validity, t1.payload  INTO newheader, validity, newpaylod 
       from jwt.view_token_type as t1 where t1.cod_type = incod_type;
   select public.uuid_generate_v4()::varchar into newcod_token;
   
   SELECT jsonb_set(newpaylod, '{"iat"}',  newepoch::text::jsonb, true) into newpaylod;
   SELECT jsonb_set(newpaylod, '{"nbf"}',  newepoch::text::jsonb, true) into newpaylod;
   SELECT jsonb_set(newpaylod, '{"exp"}', (newepoch+validity)::text::jsonb, true) into newpaylod;
   SELECT jsonb_set(newpaylod, '{"jti"}', to_jsonb(newcod_token), true) into newpaylod;
   
   insert into jwt.token ("header", payload, cod_type, cod_token, "date") values (newheader, newpaylod, incod_type, newcod_token, newdate) returning cod_token into new_token;
   
   RETURN new_token;
  end;
  

$$;


ALTER FUNCTION lib.config_token_bytype(incod_type character varying) OWNER TO easyspid;

--
-- TOC entry 2834 (class 0 OID 0)
-- Dependencies: 253
-- Name: FUNCTION config_token_bytype(incod_type character varying); Type: COMMENT; Schema: lib; Owner: easyspid
--

COMMENT ON FUNCTION config_token_bytype(incod_type character varying) IS 'Configure header and payload parts of a new token and insert them into token table. Returns cod_token';


--
-- TOC entry 251 (class 1255 OID 32948)
-- Name: create_token_bytype(character varying); Type: FUNCTION; Schema: lib; Owner: easyspid
--

CREATE FUNCTION create_token_bytype(incod_type character varying DEFAULT 'jwt1'::character varying) RETURNS character varying
    LANGUAGE plpgsql PARALLEL SAFE
    AS $$

    
    DECLARE 
      newcod_token varchar;
      newtoken text;
      newpayload jsonb;
      newheader jsonb;
      newkey text;
      newalg varchar;
    BEGIN
    
    newcod_token := (SELECT lib.config_token_bytype(incod_type));
    SELECT t1.header, t1.payload, t1.header ->> 'alg', t1.key  INTO newheader, newpayload, newalg, newkey
        FROM jwt.view_token as t1 where t1.cod_token = newcod_token;
    
    newtoken := (SELECT lib.encode_token(newpayload::text, newkey, newalg, newheader::text)); 
    UPDATE jwt.token set "token" =  newtoken WHERE cod_token = newcod_token;
    
    RETURN newcod_token;
    END;
   

$$;


ALTER FUNCTION lib.create_token_bytype(incod_type character varying) OWNER TO easyspid;

--
-- TOC entry 249 (class 1255 OID 32858)
-- Name: encode_token(text, text, character varying, text); Type: FUNCTION; Schema: lib; Owner: easyspid
--

CREATE FUNCTION encode_token(payload text, secretkey text, algorithm character varying, headers text, OUT new_token text) RETURNS text
    LANGUAGE plpython3u IMMUTABLE STRICT PARALLEL SAFE
    AS $$

  import jwt
  import simplejson
  try:
      payl = simplejson.loads(payload)
      head = simplejson.loads(headers)
      token = jwt.encode(payl, secretkey, algorithm, head)
      new_token = token.decode("utf-8")
      return new_token
  except BaseException as error:
      return "error: %s" % (error)

$$;


ALTER FUNCTION lib.encode_token(payload text, secretkey text, algorithm character varying, headers text, OUT new_token text) OWNER TO easyspid;

--
-- TOC entry 2835 (class 0 OID 0)
-- Dependencies: 249
-- Name: FUNCTION encode_token(payload text, secretkey text, algorithm character varying, headers text, OUT new_token text); Type: COMMENT; Schema: lib; Owner: easyspid
--

COMMENT ON FUNCTION encode_token(payload text, secretkey text, algorithm character varying, headers text, OUT new_token text) IS 'Simple mapping of jwt.encode function';


--
-- TOC entry 250 (class 1255 OID 32933)
-- Name: encode_token_bycod(character varying); Type: FUNCTION; Schema: lib; Owner: easyspid
--

CREATE FUNCTION encode_token_bycod(cod character varying, OUT new_token text) RETURNS text
    LANGUAGE plpython3u STABLE STRICT PARALLEL SAFE
    AS $_$

  
import jwt
import simplejson
try:
 st = "SELECT t1.header, t1.payload, t1.header ->> 'alg' as algorithm, t1.key FROM jwt.view_token as t1 where t1.cod_token = $1"
 pst = plpy.prepare(st, ["varchar"])
 query = plpy.execute(pst, [cod])
    
 if query.nrows() > 0:
  token = jwt.encode(simplejson.loads(query[0]["payload"]), query[0]["key"], query[0]["algorithm"], simplejson.loads(query[0]["header"]))
  new_token = token.decode("utf-8")
  return new_token
 else:
  return 'error: No code_token found'

except BaseException as error:
      return "error: %s" % (error)

$_$;


ALTER FUNCTION lib.encode_token_bycod(cod character varying, OUT new_token text) OWNER TO easyspid;

--
-- TOC entry 258 (class 1255 OID 77222)
-- Name: get_current_timestamp(); Type: FUNCTION; Schema: lib; Owner: easyspid
--

CREATE FUNCTION get_current_timestamp() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
NEW.date = now();
RETURN NEW;
END;
$$;


ALTER FUNCTION lib.get_current_timestamp() OWNER TO easyspid;

--
-- TOC entry 260 (class 1255 OID 93612)
-- Name: getx509cert(xml); Type: FUNCTION; Schema: lib; Owner: easyspid
--

CREATE FUNCTION getx509cert(xmldata xml) RETURNS text
    LANGUAGE plpython3u IMMUTABLE STRICT
    AS $$
from lxml import etree
    
"""
Get x509 cert of a saml assertion

:param xmlData: The element we should validate
:type: string | Document

"""
if xmldata is None or xmldata == '':
    return 'Empty string supplied as input'

parsedXml = etree.fromstring(xmldata)
cert_nodes = parsedXml.xpath(".//*[local-name()='KeyDescriptor'][@use='signing']//*[local-name()='X509Certificate']")

if len(cert_nodes) > 0:
    tmp = ("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----" % cert_nodes[0].text)
    return  tmp

else:
    return 'Could not validate metadata signature: No signature nodes found.'

$$;


ALTER FUNCTION lib.getx509cert(xmldata xml) OWNER TO easyspid;

--
-- TOC entry 246 (class 1255 OID 24594)
-- Name: jsonvalidate(jsonb, jsonb); Type: FUNCTION; Schema: lib; Owner: easyspid
--

CREATE FUNCTION jsonvalidate(jsonobj jsonb, jschema jsonb) RETURNS text
    LANGUAGE plpython3u IMMUTABLE STRICT PARALLEL SAFE
    AS $$
  from jsonschema import validate
  from jsonschema import exceptions
  import simplejson as json
  try:
      pyobj = json.loads(jsonobj)
      pyschema = json.loads(jschema)
      validate(pyobj, pyschema)
      return '0'
  except exceptions.ValidationError as error:
  #except BaseException, error:
      return "Validation error: %s\n%s" % (error.message, error.schema)
$$;


ALTER FUNCTION lib.jsonvalidate(jsonobj jsonb, jschema jsonb) OWNER TO easyspid;

--
-- TOC entry 252 (class 1255 OID 32951)
-- Name: verify_token(text, text, character varying, character varying, character varying, boolean); Type: FUNCTION; Schema: lib; Owner: easyspid
--

CREATE FUNCTION verify_token(intoken text, secretkey text, alg character varying, aud character varying, iss character varying, inverify boolean DEFAULT true, OUT new_token jsonb) RETURNS jsonb
    LANGUAGE plpython3u IMMUTABLE STRICT PARALLEL SAFE
    AS $$

  import jwt
  import simplejson
  try:
      token_jose = jwt.decode(intoken, secretkey, algorithms=alg, audience=aud, issuer=iss, verify=inverify)
      ##new_token = simplejson.dumps(token_jose)
      return simplejson.dumps({'error':0 ,'message': "%s" % (token_jose)})
      
  except jwt.exceptions.InvalidTokenError as error:
      return simplejson.dumps({'error':1 ,'message': "%s" % (error)})

$$;


ALTER FUNCTION lib.verify_token(intoken text, secretkey text, alg character varying, aud character varying, iss character varying, inverify boolean, OUT new_token jsonb) OWNER TO easyspid;

--
-- TOC entry 2836 (class 0 OID 0)
-- Dependencies: 252
-- Name: FUNCTION verify_token(intoken text, secretkey text, alg character varying, aud character varying, iss character varying, inverify boolean, OUT new_token jsonb); Type: COMMENT; Schema: lib; Owner: easyspid
--

COMMENT ON FUNCTION verify_token(intoken text, secretkey text, alg character varying, aud character varying, iss character varying, inverify boolean, OUT new_token jsonb) IS 'Simple mapping of jwt.decode function';


--
-- TOC entry 254 (class 1255 OID 32959)
-- Name: verify_token_bycod(character varying, boolean); Type: FUNCTION; Schema: lib; Owner: easyspid
--

CREATE FUNCTION verify_token_bycod(cod character varying, inverify boolean DEFAULT true, OUT new_token jsonb) RETURNS jsonb
    LANGUAGE plpython3u IMMUTABLE STRICT PARALLEL SAFE
    AS $_$

import jwt
import simplejson

try:
 st = "SELECT t1.token, t1.pubkey, t1.header->>'alg' as alg, t1.payload ->> 'aud' as aud, t1.payload ->> 'iss' as iss, t1.cod_token FROM jwt.view_token as t1 WHERE t1.cod_token = $1"
 pst = plpy.prepare(st, ["varchar"])
 query = plpy.execute(pst, [cod])
    
 if query.nrows() > 0:
  token_jose = jwt.decode(query[0]["token"], query[0]["pubkey"], algorithms=query[0]["alg"], audience=query[0]["aud"], issuer=query[0]["iss"], verify=inverify)
  #new_token = simplejson.dumps(token_jose)
  if token_jose['jti'] == query[0]["cod_token"]:
   return simplejson.dumps({'error':0 ,'message': "%s" % (token_jose)})
  else:
   return simplejson.dumps({'error':3, 'message':'jti value does not match cod_token'})
 else:
  return simplejson.dumps({'error':2, 'message':'code_token not found'})

except jwt.exceptions.InvalidTokenError as error:
    return simplejson.dumps({'error':1 ,'message': "%s" % (error)})

$_$;


ALTER FUNCTION lib.verify_token_bycod(cod character varying, inverify boolean, OUT new_token jsonb) OWNER TO easyspid;

--
-- TOC entry 256 (class 1255 OID 42032)
-- Name: x509_fingerprint(text, character varying); Type: FUNCTION; Schema: lib; Owner: easyspid
--

CREATE FUNCTION x509_fingerprint(x509cert text, alg character varying DEFAULT 'sha1'::character varying) RETURNS character varying
    LANGUAGE plpython3u IMMUTABLE STRICT
    AS $$
    from hashlib import sha1, sha256, sha384, sha512
    import base64
    
    try:
        lines = x509cert.split('\n')
        data = ''
    
        for line in lines:
            # Remove '\r' from end of line if present.
            line = line.rstrip()
            if line == '-----BEGIN CERTIFICATE-----':
                # Delete junk from before the certificate.
                data = ''
            elif line == '-----END CERTIFICATE-----':
                # Ignore data after the certificate.
                break
            elif line == '-----BEGIN PUBLIC KEY-----' or line == '-----BEGIN RSA PRIVATE KEY-----':
                # This isn't an X509 certificate.
                return  ""
            else:
                # Append the current line to the certificate data.
                data += line
    
        decoded_data = base64.b64decode(str(data))
    
        if alg == 'sha512':
            fingerprint = sha512(decoded_data)
        elif alg == 'sha384':
            fingerprint = sha384(decoded_data)
        elif alg == 'sha256':
            fingerprint = sha256(decoded_data)
        elif alg == None or alg == 'sha1':
            fingerprint = sha1(decoded_data)
        else:
            return ""
	    
        return fingerprint.hexdigest().lower()
    except BaseException as error:
        return error
       
    return ""
    
$$;


ALTER FUNCTION lib.x509_fingerprint(x509cert text, alg character varying) OWNER TO easyspid;

SET search_path = saml, pg_catalog;

--
-- TOC entry 259 (class 1255 OID 42120)
-- Name: assertions(); Type: FUNCTION; Schema: saml; Owner: easyspid
--

CREATE FUNCTION assertions() RETURNS trigger
    LANGUAGE plpgsql
    AS $_$
DECLARE 
     id_xml xml[];
     id_response xml[];
     ass_type xml[];
     newcod_token varchar;
     new_type_token varchar;
BEGIN
	
	id_xml = xpath('/*/@ID', NEW."assertion");
	id_response = xpath('/*/@InResponseTo', NEW."assertion");
	ass_type = xpath('name(/*)', NEW."assertion");
	--newcod_token := (SELECT lib.create_token_bytype('jwt2'));

	IF coalesce(array_upper(ass_type, 1), 0) > 0 THEN
		--UPDATE saml.assertions SET ID_assertion = xmlserialize(CONTENT id_xml[1] as character varying), 
		--cod_type[1] = xmlserialize(CONTENT ass_type as character varying) WHERE "ID" = NEW."ID";
		--UPDATE saml.assertions SET "ID_assertion" = xmlserialize(CONTENT id_xml[1] as character varying) WHERE "ID" = NEW."ID";
		NEW."cod_type" = substring(xmlserialize(CONTENT ass_type[1] as character varying) from '[^:]+$');
		NEW."ID_assertion" = xmlserialize(CONTENT id_xml[1] as character varying);
		NEW."ID_response_assertion" = xmlserialize(CONTENT id_response[1] as character varying);
		SELECT t1.cod_type_token INTO new_type_token FROM saml.jwt_settings as t1 
				WHERE t1.cod_provider = NEW.cod_sp and t1.cod_type_assertion = NEW."cod_type";
		newcod_token := (SELECT lib.create_token_bytype(new_type_token));
		NEW."cod_token" = newcod_token;
	END IF;

	RETURN NEW;
END;
$_$;


ALTER FUNCTION saml.assertions() OWNER TO easyspid;

--
-- TOC entry 257 (class 1255 OID 42033)
-- Name: get_x509_fingerprint(); Type: FUNCTION; Schema: saml; Owner: easyspid
--

CREATE FUNCTION get_x509_fingerprint() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
NEW.fingerprint = lib.x509_fingerprint(NEW.public_key, NEW.fingerprintalg);
RETURN NEW;
END;
$$;


ALTER FUNCTION saml.get_x509_fingerprint() OWNER TO easyspid;

--
-- TOC entry 261 (class 1255 OID 93614)
-- Name: getx509cert(); Type: FUNCTION; Schema: saml; Owner: easyspid
--

CREATE FUNCTION getx509cert() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE 
     codCert varchar;
     certx509 text;
BEGIN

	SELECT INTO certx509 lib.getx509Cert(NEW.xml);
	SELECT cod_cert INTO codCert FROM saml.signatures WHERE cod_provider = NEW.cod_provider;

	IF codCert is NULL THEN
	    INSERT INTO saml.signatures (cod_cert, cod_provider, public_key) VALUES ('cert_'||NEW.cod_provider, NEW.cod_provider, certx509);
	END IF;

	IF codCert is NOT NULL THEN
	    UPDATE saml.signatures SET public_key = certx509 WHERE cod_cert = codCert;
	END IF;

	RETURN NEW;
END;
$$;


ALTER FUNCTION saml.getx509cert() OWNER TO easyspid;

SET search_path = jwt, pg_catalog;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- TOC entry 192 (class 1259 OID 24579)
-- Name: token; Type: TABLE; Schema: jwt; Owner: easyspid
--

CREATE TABLE token (
    cod_token character varying(255) DEFAULT public.uuid_generate_v4() NOT NULL,
    header jsonb NOT NULL,
    payload jsonb NOT NULL,
    token text,
    "ID" integer NOT NULL,
    cod_type character varying(50) DEFAULT 'jwt1'::character varying NOT NULL,
    date timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE token OWNER TO easyspid;

--
-- TOC entry 191 (class 1259 OID 24577)
-- Name: token_ID_seq; Type: SEQUENCE; Schema: jwt; Owner: easyspid
--

CREATE SEQUENCE "token_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE "token_ID_seq" OWNER TO easyspid;

--
-- TOC entry 2837 (class 0 OID 0)
-- Dependencies: 191
-- Name: token_ID_seq; Type: SEQUENCE OWNED BY; Schema: jwt; Owner: easyspid
--

ALTER SEQUENCE "token_ID_seq" OWNED BY token."ID";


--
-- TOC entry 200 (class 1259 OID 32887)
-- Name: token_payload; Type: TABLE; Schema: jwt; Owner: easyspid
--

CREATE TABLE token_payload (
    "ID" integer NOT NULL,
    cod_payload character varying(50) DEFAULT public.uuid_generate_v4() NOT NULL,
    cod_type character varying(50) DEFAULT 'jwt1'::character varying NOT NULL,
    payload jsonb DEFAULT '{"aud": "Service Provider", "exp": 1, "iat": 1, "iss": "EasySPID", "nbf": 1, "sub": "saml assertion validator"}'::jsonb NOT NULL
);


ALTER TABLE token_payload OWNER TO easyspid;

--
-- TOC entry 199 (class 1259 OID 32885)
-- Name: token_payload_ID_seq; Type: SEQUENCE; Schema: jwt; Owner: easyspid
--

CREATE SEQUENCE "token_payload_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE "token_payload_ID_seq" OWNER TO easyspid;

--
-- TOC entry 2838 (class 0 OID 0)
-- Dependencies: 199
-- Name: token_payload_ID_seq; Type: SEQUENCE OWNED BY; Schema: jwt; Owner: easyspid
--

ALTER SEQUENCE "token_payload_ID_seq" OWNED BY token_payload."ID";


--
-- TOC entry 194 (class 1259 OID 24605)
-- Name: token_schemas; Type: TABLE; Schema: jwt; Owner: easyspid
--

CREATE TABLE token_schemas (
    "ID" integer NOT NULL,
    cod_schema character varying(255) DEFAULT public.uuid_generate_v4() NOT NULL,
    schema jsonb NOT NULL,
    active boolean DEFAULT true NOT NULL,
    note text,
    cod_type character varying(50) DEFAULT 'jwt1'::character varying NOT NULL,
    part character varying(50),
    CONSTRAINT token_schemas_part_check CHECK ((((part)::text = 'header'::text) OR ((part)::text = 'payload'::text)))
);


ALTER TABLE token_schemas OWNER TO easyspid;

--
-- TOC entry 193 (class 1259 OID 24603)
-- Name: token_schemas_ID_seq; Type: SEQUENCE; Schema: jwt; Owner: easyspid
--

CREATE SEQUENCE "token_schemas_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE "token_schemas_ID_seq" OWNER TO easyspid;

--
-- TOC entry 2839 (class 0 OID 0)
-- Dependencies: 193
-- Name: token_schemas_ID_seq; Type: SEQUENCE OWNED BY; Schema: jwt; Owner: easyspid
--

ALTER SEQUENCE "token_schemas_ID_seq" OWNED BY token_schemas."ID";


--
-- TOC entry 198 (class 1259 OID 32805)
-- Name: token_signature; Type: TABLE; Schema: jwt; Owner: easyspid
--

CREATE TABLE token_signature (
    "ID" integer NOT NULL,
    cod_signature character varying(50) DEFAULT public.uuid_generate_v4() NOT NULL,
    key text DEFAULT 'bellapetutti'::text NOT NULL,
    cod_type character varying(50) DEFAULT 'jwt1'::character varying NOT NULL,
    validity integer DEFAULT 1200 NOT NULL,
    header jsonb DEFAULT '{"alg": "HS256", "typ": "JWT"}'::jsonb NOT NULL,
    pubkey text
);


ALTER TABLE token_signature OWNER TO easyspid;

--
-- TOC entry 197 (class 1259 OID 32803)
-- Name: token_signature_ID_seq; Type: SEQUENCE; Schema: jwt; Owner: easyspid
--

CREATE SEQUENCE "token_signature_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE "token_signature_ID_seq" OWNER TO easyspid;

--
-- TOC entry 2840 (class 0 OID 0)
-- Dependencies: 197
-- Name: token_signature_ID_seq; Type: SEQUENCE OWNED BY; Schema: jwt; Owner: easyspid
--

ALTER SEQUENCE "token_signature_ID_seq" OWNED BY token_signature."ID";


--
-- TOC entry 196 (class 1259 OID 32791)
-- Name: token_type; Type: TABLE; Schema: jwt; Owner: easyspid
--

CREATE TABLE token_type (
    "ID" integer NOT NULL,
    cod_type character varying(50) DEFAULT public.uuid_generate_v4() NOT NULL,
    note text
);


ALTER TABLE token_type OWNER TO easyspid;

--
-- TOC entry 195 (class 1259 OID 32789)
-- Name: token_type_ID_seq; Type: SEQUENCE; Schema: jwt; Owner: easyspid
--

CREATE SEQUENCE "token_type_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE "token_type_ID_seq" OWNER TO easyspid;

--
-- TOC entry 2841 (class 0 OID 0)
-- Dependencies: 195
-- Name: token_type_ID_seq; Type: SEQUENCE OWNED BY; Schema: jwt; Owner: easyspid
--

ALTER SEQUENCE "token_type_ID_seq" OWNED BY token_type."ID";


--
-- TOC entry 201 (class 1259 OID 32960)
-- Name: view_token; Type: VIEW; Schema: jwt; Owner: easyspid
--

CREATE VIEW view_token AS
 SELECT t1.cod_token,
    t1.header,
    t1.payload,
    t1.token,
    t1."ID",
    t1.cod_type,
    t1.date,
    t2.key,
    t2.pubkey,
    t2.validity
   FROM (token t1
     LEFT JOIN token_signature t2 ON (((t2.cod_type)::text = (t1.cod_type)::text)));


ALTER TABLE view_token OWNER TO easyspid;

--
-- TOC entry 202 (class 1259 OID 32964)
-- Name: view_token_type; Type: VIEW; Schema: jwt; Owner: easyspid
--

CREATE VIEW view_token_type AS
 SELECT t1."ID",
    t1.cod_type,
    t1.note,
    t2.header,
    t2.validity,
    t2.key,
    t2.pubkey,
    t3.payload
   FROM ((token_type t1
     LEFT JOIN token_signature t2 ON (((t2.cod_type)::text = (t1.cod_type)::text)))
     LEFT JOIN token_payload t3 ON (((t3.cod_type)::text = (t1.cod_type)::text)));


ALTER TABLE view_token_type OWNER TO easyspid;

SET search_path = log, pg_catalog;

--
-- TOC entry 221 (class 1259 OID 77209)
-- Name: requests; Type: TABLE; Schema: log; Owner: easyspid
--

CREATE TABLE requests (
    "ID" integer NOT NULL,
    cod_request character varying(50) DEFAULT public.uuid_generate_v4() NOT NULL,
    http_verb character varying(50) NOT NULL,
    url text NOT NULL,
    date timestamp with time zone DEFAULT now() NOT NULL,
    client inet NOT NULL,
    request text
);


ALTER TABLE requests OWNER TO easyspid;

--
-- TOC entry 220 (class 1259 OID 77207)
-- Name: request_ID_seq; Type: SEQUENCE; Schema: log; Owner: easyspid
--

CREATE SEQUENCE "request_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE "request_ID_seq" OWNER TO easyspid;

--
-- TOC entry 2842 (class 0 OID 0)
-- Dependencies: 220
-- Name: request_ID_seq; Type: SEQUENCE OWNED BY; Schema: log; Owner: easyspid
--

ALTER SEQUENCE "request_ID_seq" OWNED BY requests."ID";


--
-- TOC entry 223 (class 1259 OID 77258)
-- Name: responses; Type: TABLE; Schema: log; Owner: easyspid
--

CREATE TABLE responses (
    "ID" integer NOT NULL,
    cod_response character varying(50) DEFAULT public.uuid_generate_v4() NOT NULL,
    http_code character varying(50) NOT NULL,
    url_origin text NOT NULL,
    date timestamp with time zone DEFAULT now() NOT NULL,
    client inet NOT NULL,
    response text
);


ALTER TABLE responses OWNER TO easyspid;

--
-- TOC entry 222 (class 1259 OID 77256)
-- Name: respones_ID_seq; Type: SEQUENCE; Schema: log; Owner: easyspid
--

CREATE SEQUENCE "respones_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE "respones_ID_seq" OWNER TO easyspid;

--
-- TOC entry 2843 (class 0 OID 0)
-- Dependencies: 222
-- Name: respones_ID_seq; Type: SEQUENCE OWNED BY; Schema: log; Owner: easyspid
--

ALTER SEQUENCE "respones_ID_seq" OWNED BY responses."ID";


SET search_path = saml, pg_catalog;

--
-- TOC entry 208 (class 1259 OID 33876)
-- Name: assertions; Type: TABLE; Schema: saml; Owner: easyspid
--

CREATE TABLE assertions (
    "ID" integer NOT NULL,
    cod_assertion character varying(50) DEFAULT public.uuid_generate_v4() NOT NULL,
    assertion xml NOT NULL,
    cod_token character varying(50) NOT NULL,
    cod_type character varying(50) NOT NULL,
    date timestamp with time zone DEFAULT now() NOT NULL,
    "ID_assertion" character varying(200),
    cod_sp character varying,
    cod_idp character varying,
    client inet,
    "ID_response_assertion" character varying(200)
);


ALTER TABLE assertions OWNER TO easyspid;

--
-- TOC entry 207 (class 1259 OID 33874)
-- Name: assertions_ID_seq; Type: SEQUENCE; Schema: saml; Owner: easyspid
--

CREATE SEQUENCE "assertions_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE "assertions_ID_seq" OWNER TO easyspid;

--
-- TOC entry 2844 (class 0 OID 0)
-- Dependencies: 207
-- Name: assertions_ID_seq; Type: SEQUENCE OWNED BY; Schema: saml; Owner: easyspid
--

ALTER SEQUENCE "assertions_ID_seq" OWNED BY assertions."ID";


--
-- TOC entry 210 (class 1259 OID 33968)
-- Name: assertions_type; Type: TABLE; Schema: saml; Owner: easyspid
--

CREATE TABLE assertions_type (
    "ID" integer NOT NULL,
    cod_type character varying(50) DEFAULT public.uuid_generate_v4() NOT NULL,
    type character varying(255) NOT NULL
);


ALTER TABLE assertions_type OWNER TO easyspid;

--
-- TOC entry 209 (class 1259 OID 33966)
-- Name: assertions_type_ID_seq; Type: SEQUENCE; Schema: saml; Owner: easyspid
--

CREATE SEQUENCE "assertions_type_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE "assertions_type_ID_seq" OWNER TO easyspid;

--
-- TOC entry 2845 (class 0 OID 0)
-- Dependencies: 209
-- Name: assertions_type_ID_seq; Type: SEQUENCE OWNED BY; Schema: saml; Owner: easyspid
--

ALTER SEQUENCE "assertions_type_ID_seq" OWNED BY assertions_type."ID";


--
-- TOC entry 206 (class 1259 OID 33855)
-- Name: signatures; Type: TABLE; Schema: saml; Owner: easyspid
--

CREATE TABLE signatures (
    "ID" integer NOT NULL,
    cod_cert character varying(50) DEFAULT public.uuid_generate_v4() NOT NULL,
    private_key text,
    public_key text NOT NULL,
    cod_provider character varying(50) NOT NULL,
    date timestamp with time zone DEFAULT now() NOT NULL,
    fingerprint text NOT NULL,
    fingerprintalg character varying(50) DEFAULT 'sha1'::character varying NOT NULL,
    CONSTRAINT signatures_fingerprintalg_check CHECK (((fingerprintalg)::text = ANY ((ARRAY['sha1'::character varying, 'sha256'::character varying, 'sha384'::character varying, 'sha512'::character varying])::text[])))
);


ALTER TABLE signatures OWNER TO easyspid;

--
-- TOC entry 2846 (class 0 OID 0)
-- Dependencies: 206
-- Name: COLUMN signatures.private_key; Type: COMMENT; Schema: saml; Owner: easyspid
--

COMMENT ON COLUMN signatures.private_key IS 'x509 public key';


--
-- TOC entry 2847 (class 0 OID 0)
-- Dependencies: 206
-- Name: COLUMN signatures.public_key; Type: COMMENT; Schema: saml; Owner: easyspid
--

COMMENT ON COLUMN signatures.public_key IS 'x509 PEM encoded certificate';


--
-- TOC entry 2848 (class 0 OID 0)
-- Dependencies: 206
-- Name: COLUMN signatures.fingerprint; Type: COMMENT; Schema: saml; Owner: easyspid
--

COMMENT ON COLUMN signatures.fingerprint IS 'base64 encoded x509 certificate hash';


--
-- TOC entry 2849 (class 0 OID 0)
-- Dependencies: 206
-- Name: COLUMN signatures.fingerprintalg; Type: COMMENT; Schema: saml; Owner: easyspid
--

COMMENT ON COLUMN signatures.fingerprintalg IS 'algorithm to use in fingerprint hashing';


--
-- TOC entry 205 (class 1259 OID 33853)
-- Name: certifcates_ID_seq; Type: SEQUENCE; Schema: saml; Owner: easyspid
--

CREATE SEQUENCE "certifcates_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE "certifcates_ID_seq" OWNER TO easyspid;

--
-- TOC entry 2850 (class 0 OID 0)
-- Dependencies: 205
-- Name: certifcates_ID_seq; Type: SEQUENCE OWNED BY; Schema: saml; Owner: easyspid
--

ALTER SEQUENCE "certifcates_ID_seq" OWNED BY signatures."ID";


--
-- TOC entry 218 (class 1259 OID 42292)
-- Name: jwt_settings; Type: TABLE; Schema: saml; Owner: easyspid
--

CREATE TABLE jwt_settings (
    "ID" integer NOT NULL,
    cod_jwt_setting character varying(50) DEFAULT public.uuid_generate_v4() NOT NULL,
    cod_provider character varying(50) NOT NULL,
    cod_type_assertion character varying(50) NOT NULL,
    cod_type_token character varying(50)
);


ALTER TABLE jwt_settings OWNER TO easyspid;

--
-- TOC entry 217 (class 1259 OID 42290)
-- Name: jwt_settings_ID_seq; Type: SEQUENCE; Schema: saml; Owner: easyspid
--

CREATE SEQUENCE "jwt_settings_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE "jwt_settings_ID_seq" OWNER TO easyspid;

--
-- TOC entry 2851 (class 0 OID 0)
-- Dependencies: 217
-- Name: jwt_settings_ID_seq; Type: SEQUENCE OWNED BY; Schema: saml; Owner: easyspid
--

ALTER SEQUENCE "jwt_settings_ID_seq" OWNED BY jwt_settings."ID";


--
-- TOC entry 214 (class 1259 OID 34628)
-- Name: metadata; Type: TABLE; Schema: saml; Owner: easyspid
--

CREATE TABLE metadata (
    "ID" integer NOT NULL,
    cod_metadata character varying(50) DEFAULT public.uuid_generate_v4() NOT NULL,
    xml xml,
    date timestamp with time zone DEFAULT now() NOT NULL,
    note text,
    active boolean DEFAULT true NOT NULL,
    cod_provider character varying(50) NOT NULL,
    CONSTRAINT metadata_active_check CHECK (((active = true) OR (active = false)))
);


ALTER TABLE metadata OWNER TO easyspid;

--
-- TOC entry 2852 (class 0 OID 0)
-- Dependencies: 214
-- Name: TABLE metadata; Type: COMMENT; Schema: saml; Owner: easyspid
--

COMMENT ON TABLE metadata IS 'Put here Identity Providers Metadata';


--
-- TOC entry 213 (class 1259 OID 34626)
-- Name: metadata_ID_seq; Type: SEQUENCE; Schema: saml; Owner: easyspid
--

CREATE SEQUENCE "metadata_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE "metadata_ID_seq" OWNER TO easyspid;

--
-- TOC entry 2853 (class 0 OID 0)
-- Dependencies: 213
-- Name: metadata_ID_seq; Type: SEQUENCE OWNED BY; Schema: saml; Owner: easyspid
--

ALTER SEQUENCE "metadata_ID_seq" OWNED BY metadata."ID";


--
-- TOC entry 204 (class 1259 OID 33836)
-- Name: providers; Type: TABLE; Schema: saml; Owner: easyspid
--

CREATE TABLE providers (
    "ID" integer NOT NULL,
    cod_provider character varying(50) DEFAULT public.uuid_generate_v4() NOT NULL,
    type character varying(255) DEFAULT 'idp'::character varying NOT NULL,
    description text,
    active boolean DEFAULT true NOT NULL,
    date timestamp with time zone DEFAULT now(),
    name character varying(255) NOT NULL,
    CONSTRAINT providers_active_check CHECK (((active = true) OR (active = false))),
    CONSTRAINT providers_type_check CHECK ((((type)::text = 'idp'::text) OR ((type)::text = 'sp'::text) OR ((type)::text = 'gw'::text)))
);


ALTER TABLE providers OWNER TO easyspid;

--
-- TOC entry 203 (class 1259 OID 33834)
-- Name: providers_ID_seq; Type: SEQUENCE; Schema: saml; Owner: easyspid
--

CREATE SEQUENCE "providers_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE "providers_ID_seq" OWNER TO easyspid;

--
-- TOC entry 2854 (class 0 OID 0)
-- Dependencies: 203
-- Name: providers_ID_seq; Type: SEQUENCE OWNED BY; Schema: saml; Owner: easyspid
--

ALTER SEQUENCE "providers_ID_seq" OWNED BY providers."ID";


--
-- TOC entry 212 (class 1259 OID 33992)
-- Name: services; Type: TABLE; Schema: saml; Owner: easyspid
--

CREATE TABLE services (
    "ID" integer NOT NULL,
    cod_service character varying(50) DEFAULT public.uuid_generate_v4() NOT NULL,
    name text NOT NULL,
    description text,
    cod_provider character varying(50) NOT NULL,
    active boolean DEFAULT true NOT NULL,
    url character varying(255) NOT NULL,
    CONSTRAINT services_active_check CHECK (((active = true) OR (active = false)))
);


ALTER TABLE services OWNER TO easyspid;

--
-- TOC entry 2855 (class 0 OID 0)
-- Dependencies: 212
-- Name: TABLE services; Type: COMMENT; Schema: saml; Owner: easyspid
--

COMMENT ON TABLE services IS 'Services requestd by user to service provider';


--
-- TOC entry 211 (class 1259 OID 33990)
-- Name: services_ID_seq; Type: SEQUENCE; Schema: saml; Owner: easyspid
--

CREATE SEQUENCE "services_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE "services_ID_seq" OWNER TO easyspid;

--
-- TOC entry 2856 (class 0 OID 0)
-- Dependencies: 211
-- Name: services_ID_seq; Type: SEQUENCE OWNED BY; Schema: saml; Owner: easyspid
--

ALTER SEQUENCE "services_ID_seq" OWNED BY services."ID";


--
-- TOC entry 216 (class 1259 OID 42085)
-- Name: settings; Type: TABLE; Schema: saml; Owner: easyspid
--

CREATE TABLE settings (
    "ID" integer NOT NULL,
    cod_setting character varying(50) DEFAULT public.uuid_generate_v4() NOT NULL,
    active boolean DEFAULT true NOT NULL,
    cod_provider character varying(50) NOT NULL,
    settings jsonb,
    advanced_settings jsonb,
    date timestamp with time zone DEFAULT now() NOT NULL,
    note text,
    CONSTRAINT setting_active_check CHECK (((active = true) OR (active = false)))
);


ALTER TABLE settings OWNER TO easyspid;

--
-- TOC entry 2857 (class 0 OID 0)
-- Dependencies: 216
-- Name: TABLE settings; Type: COMMENT; Schema: saml; Owner: easyspid
--

COMMENT ON TABLE settings IS 'Service Providers settings';


--
-- TOC entry 215 (class 1259 OID 42083)
-- Name: settings_ID_seq; Type: SEQUENCE; Schema: saml; Owner: easyspid
--

CREATE SEQUENCE "settings_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE "settings_ID_seq" OWNER TO easyspid;

--
-- TOC entry 2858 (class 0 OID 0)
-- Dependencies: 215
-- Name: settings_ID_seq; Type: SEQUENCE OWNED BY; Schema: saml; Owner: easyspid
--

ALTER SEQUENCE "settings_ID_seq" OWNED BY settings."ID";


--
-- TOC entry 219 (class 1259 OID 50643)
-- Name: view_assertions; Type: VIEW; Schema: saml; Owner: easyspid
--

CREATE VIEW view_assertions AS
 SELECT t1."ID",
    t1.cod_assertion,
    t1.assertion,
    t1.cod_token,
    t2.cod_type AS cod_type_token,
    t2.token,
    t1.cod_type,
    t1.date,
    t1."ID_assertion",
    t1."ID_response_assertion",
    t1.cod_sp,
    t1.cod_idp,
    t1.client
   FROM (assertions t1
     LEFT JOIN jwt.token t2 ON (((t2.cod_token)::text = (t1.cod_token)::text)));


ALTER TABLE view_assertions OWNER TO easyspid;

SET search_path = jwt, pg_catalog;

--
-- TOC entry 2498 (class 2604 OID 24582)
-- Name: token ID; Type: DEFAULT; Schema: jwt; Owner: easyspid
--

ALTER TABLE ONLY token ALTER COLUMN "ID" SET DEFAULT nextval('"token_ID_seq"'::regclass);


--
-- TOC entry 2515 (class 2604 OID 32890)
-- Name: token_payload ID; Type: DEFAULT; Schema: jwt; Owner: easyspid
--

ALTER TABLE ONLY token_payload ALTER COLUMN "ID" SET DEFAULT nextval('"token_payload_ID_seq"'::regclass);


--
-- TOC entry 2502 (class 2604 OID 24608)
-- Name: token_schemas ID; Type: DEFAULT; Schema: jwt; Owner: easyspid
--

ALTER TABLE ONLY token_schemas ALTER COLUMN "ID" SET DEFAULT nextval('"token_schemas_ID_seq"'::regclass);


--
-- TOC entry 2509 (class 2604 OID 32808)
-- Name: token_signature ID; Type: DEFAULT; Schema: jwt; Owner: easyspid
--

ALTER TABLE ONLY token_signature ALTER COLUMN "ID" SET DEFAULT nextval('"token_signature_ID_seq"'::regclass);


--
-- TOC entry 2507 (class 2604 OID 32794)
-- Name: token_type ID; Type: DEFAULT; Schema: jwt; Owner: easyspid
--

ALTER TABLE ONLY token_type ALTER COLUMN "ID" SET DEFAULT nextval('"token_type_ID_seq"'::regclass);


SET search_path = log, pg_catalog;

--
-- TOC entry 2552 (class 2604 OID 77212)
-- Name: requests ID; Type: DEFAULT; Schema: log; Owner: easyspid
--

ALTER TABLE ONLY requests ALTER COLUMN "ID" SET DEFAULT nextval('"request_ID_seq"'::regclass);


--
-- TOC entry 2555 (class 2604 OID 77261)
-- Name: responses ID; Type: DEFAULT; Schema: log; Owner: easyspid
--

ALTER TABLE ONLY responses ALTER COLUMN "ID" SET DEFAULT nextval('"respones_ID_seq"'::regclass);


SET search_path = saml, pg_catalog;

--
-- TOC entry 2531 (class 2604 OID 33879)
-- Name: assertions ID; Type: DEFAULT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY assertions ALTER COLUMN "ID" SET DEFAULT nextval('"assertions_ID_seq"'::regclass);


--
-- TOC entry 2534 (class 2604 OID 33971)
-- Name: assertions_type ID; Type: DEFAULT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY assertions_type ALTER COLUMN "ID" SET DEFAULT nextval('"assertions_type_ID_seq"'::regclass);


--
-- TOC entry 2550 (class 2604 OID 42295)
-- Name: jwt_settings ID; Type: DEFAULT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY jwt_settings ALTER COLUMN "ID" SET DEFAULT nextval('"jwt_settings_ID_seq"'::regclass);


--
-- TOC entry 2540 (class 2604 OID 34631)
-- Name: metadata ID; Type: DEFAULT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY metadata ALTER COLUMN "ID" SET DEFAULT nextval('"metadata_ID_seq"'::regclass);


--
-- TOC entry 2519 (class 2604 OID 33839)
-- Name: providers ID; Type: DEFAULT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY providers ALTER COLUMN "ID" SET DEFAULT nextval('"providers_ID_seq"'::regclass);


--
-- TOC entry 2536 (class 2604 OID 33995)
-- Name: services ID; Type: DEFAULT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY services ALTER COLUMN "ID" SET DEFAULT nextval('"services_ID_seq"'::regclass);


--
-- TOC entry 2545 (class 2604 OID 42088)
-- Name: settings ID; Type: DEFAULT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY settings ALTER COLUMN "ID" SET DEFAULT nextval('"settings_ID_seq"'::regclass);


--
-- TOC entry 2526 (class 2604 OID 33858)
-- Name: signatures ID; Type: DEFAULT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY signatures ALTER COLUMN "ID" SET DEFAULT nextval('"certifcates_ID_seq"'::regclass);


SET search_path = jwt, pg_catalog;

--
-- TOC entry 2796 (class 0 OID 24579)
-- Dependencies: 192
-- Data for Name: token; Type: TABLE DATA; Schema: jwt; Owner: easyspid
--

INSERT INTO token (cod_token, header, payload, token, "ID", cod_type, date) VALUES ('dff0660b-85d7-4951-ae2e-fce2b012aec6', '{"alg": "HS256", "typ": "JWT"}', '{"aud": "Service Providers using EasySPID API", "exp": 1500218148, "iat": 1500216948, "iss": "EasySPID gateway", "jti": "dff0660b-85d7-4951-ae2e-fce2b012aec6", "nbf": 1500216948, "sub": "Access to EasySPID API"}', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDAyMTgxNDgsImlhdCI6MTUwMDIxNjk0OCwiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6ImRmZjA2NjBiLTg1ZDctNDk1MS1hZTJlLWZjZTJiMDEyYWVjNiIsIm5iZiI6MTUwMDIxNjk0OCwic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.WjreBcn-YyaAXXgySR0nPWLi0dAjEFm5FBkgWCSyzSI', 6444, 'jwt1', '2017-07-16 16:55:47.751294+02');
INSERT INTO token (cod_token, header, payload, token, "ID", cod_type, date) VALUES ('8624527f-8a70-4bc5-aff7-7712f6ea35c9', '{"alg": "HS256", "typ": "JWT"}', '{"aud": "Service Providers using EasySPID API", "exp": 1500218196, "iat": 1500216996, "iss": "EasySPID gateway", "jti": "8624527f-8a70-4bc5-aff7-7712f6ea35c9", "nbf": 1500216996, "sub": "Access to EasySPID API"}', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDAyMTgxOTYsImlhdCI6MTUwMDIxNjk5NiwiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6Ijg2MjQ1MjdmLThhNzAtNGJjNS1hZmY3LTc3MTJmNmVhMzVjOSIsIm5iZiI6MTUwMDIxNjk5Niwic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.YmMaSFhUmEjyp6JYHpsM3KCwCq10nUGN-V5Qc1i6tnw', 6445, 'jwt1', '2017-07-16 16:56:36.4118+02');
INSERT INTO token (cod_token, header, payload, token, "ID", cod_type, date) VALUES ('dbc6a861-abdf-47f8-b709-463240f66571', '{"alg": "HS256", "typ": "JWT"}', '{"aud": "Service Providers using EasySPID API", "exp": 1500218338, "iat": 1500217138, "iss": "EasySPID gateway", "jti": "dbc6a861-abdf-47f8-b709-463240f66571", "nbf": 1500217138, "sub": "Access to EasySPID API"}', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDAyMTgzMzgsImlhdCI6MTUwMDIxNzEzOCwiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6ImRiYzZhODYxLWFiZGYtNDdmOC1iNzA5LTQ2MzI0MGY2NjU3MSIsIm5iZiI6MTUwMDIxNzEzOCwic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.PkRbauTUwRz73zVCIHbdpGgHsu5lelzZaAwlHJPrDoc', 6446, 'jwt1', '2017-07-16 16:58:57.887436+02');
INSERT INTO token (cod_token, header, payload, token, "ID", cod_type, date) VALUES ('28ee865a-5ed0-432d-a210-af1416c1e1ed', '{"alg": "HS256", "typ": "JWT"}', '{"aud": "Service Providers using EasySPID API", "exp": 1500218466, "iat": 1500217266, "iss": "EasySPID gateway", "jti": "28ee865a-5ed0-432d-a210-af1416c1e1ed", "nbf": 1500217266, "sub": "Access to EasySPID API"}', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDAyMTg0NjYsImlhdCI6MTUwMDIxNzI2NiwiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6IjI4ZWU4NjVhLTVlZDAtNDMyZC1hMjEwLWFmMTQxNmMxZTFlZCIsIm5iZiI6MTUwMDIxNzI2Niwic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.ucLRurYAk3YTt9Pyi2feYG7glD09Avtst8PuVARk-Eo', 6447, 'jwt1', '2017-07-16 17:01:05.508382+02');
INSERT INTO token (cod_token, header, payload, token, "ID", cod_type, date) VALUES ('acd31a9a-580d-4e2d-be31-b14258a151d8', '{"alg": "HS256", "typ": "JWT"}', '{"aud": "Service Providers using EasySPID API", "exp": 1500218806, "iat": 1500217606, "iss": "EasySPID gateway", "jti": "acd31a9a-580d-4e2d-be31-b14258a151d8", "nbf": 1500217606, "sub": "Access to EasySPID API"}', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDAyMTg4MDYsImlhdCI6MTUwMDIxNzYwNiwiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6ImFjZDMxYTlhLTU4MGQtNGUyZC1iZTMxLWIxNDI1OGExNTFkOCIsIm5iZiI6MTUwMDIxNzYwNiwic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.R9honV89wBKx_i5akAYWZx_OqNFrbwD54TPwKjZjjWg', 6448, 'jwt1', '2017-07-16 17:06:46.3995+02');
INSERT INTO token (cod_token, header, payload, token, "ID", cod_type, date) VALUES ('dca1e3bf-1e54-44f1-8243-e329ae2d839c', '{"alg": "HS256", "typ": "JWT"}', '{"aud": "Service Providers using EasySPID API", "exp": 1500218859, "iat": 1500217659, "iss": "EasySPID gateway", "jti": "dca1e3bf-1e54-44f1-8243-e329ae2d839c", "nbf": 1500217659, "sub": "Access to EasySPID API"}', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDAyMTg4NTksImlhdCI6MTUwMDIxNzY1OSwiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6ImRjYTFlM2JmLTFlNTQtNDRmMS04MjQzLWUzMjlhZTJkODM5YyIsIm5iZiI6MTUwMDIxNzY1OSwic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.fd1t4xc1_mMrAVXQXg4iLMbky5zzuoxQUqxTCkeSrtw', 6449, 'jwt1', '2017-07-16 17:07:39.271319+02');
INSERT INTO token (cod_token, header, payload, token, "ID", cod_type, date) VALUES ('01e89f6f-3446-44e4-8d24-2b221a04157d', '{"alg": "HS256", "typ": "JWT"}', '{"aud": "Service Providers using EasySPID API", "exp": 1500218916, "iat": 1500217716, "iss": "EasySPID gateway", "jti": "01e89f6f-3446-44e4-8d24-2b221a04157d", "nbf": 1500217716, "sub": "Access to EasySPID API"}', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDAyMTg5MTYsImlhdCI6MTUwMDIxNzcxNiwiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6IjAxZTg5ZjZmLTM0NDYtNDRlNC04ZDI0LTJiMjIxYTA0MTU3ZCIsIm5iZiI6MTUwMDIxNzcxNiwic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.N6qqUTcraYfeB1t8AiucBTLe7dzdxtKsYff7zYxjdYI', 6450, 'jwt1', '2017-07-16 17:08:36.421276+02');
INSERT INTO token (cod_token, header, payload, token, "ID", cod_type, date) VALUES ('9ee89bf0-c783-4bba-a951-fdbd865115a4', '{"alg": "HS256", "typ": "JWT"}', '{"aud": "Service Providers using EasySPID API", "exp": 1500219007, "iat": 1500217807, "iss": "EasySPID gateway", "jti": "9ee89bf0-c783-4bba-a951-fdbd865115a4", "nbf": 1500217807, "sub": "Access to EasySPID API"}', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDAyMTkwMDcsImlhdCI6MTUwMDIxNzgwNywiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6IjllZTg5YmYwLWM3ODMtNGJiYS1hOTUxLWZkYmQ4NjUxMTVhNCIsIm5iZiI6MTUwMDIxNzgwNywic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.2lQwoTr5ibxAEGPHIhAQRaXcyRNjBvg9NyFzkVW_ot4', 6451, 'jwt1', '2017-07-16 17:10:06.940292+02');
INSERT INTO token (cod_token, header, payload, token, "ID", cod_type, date) VALUES ('7aa04f18-3d7e-4d34-b7e2-3f668e34320f', '{"alg": "HS256", "typ": "JWT"}', '{"aud": "Service Providers using EasySPID API", "exp": 1500219163, "iat": 1500217963, "iss": "EasySPID gateway", "jti": "7aa04f18-3d7e-4d34-b7e2-3f668e34320f", "nbf": 1500217963, "sub": "Access to EasySPID API"}', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDAyMTkxNjMsImlhdCI6MTUwMDIxNzk2MywiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6IjdhYTA0ZjE4LTNkN2UtNGQzNC1iN2UyLTNmNjY4ZTM0MzIwZiIsIm5iZiI6MTUwMDIxNzk2Mywic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.RbffZN7LysSuScq_m8sw9Jbs7vEQdK2P3dPI5_CPz90', 6452, 'jwt1', '2017-07-16 17:12:42.585708+02');
INSERT INTO token (cod_token, header, payload, token, "ID", cod_type, date) VALUES ('32daabc9-34e0-46a9-8797-34ce00c99c6f', '{"alg": "HS256", "typ": "JWT"}', '{"aud": "Service Providers using EasySPID API", "exp": 1500219202, "iat": 1500218002, "iss": "EasySPID gateway", "jti": "32daabc9-34e0-46a9-8797-34ce00c99c6f", "nbf": 1500218002, "sub": "Access to EasySPID API"}', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDAyMTkyMDIsImlhdCI6MTUwMDIxODAwMiwiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6IjMyZGFhYmM5LTM0ZTAtNDZhOS04Nzk3LTM0Y2UwMGM5OWM2ZiIsIm5iZiI6MTUwMDIxODAwMiwic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.n0SEgMvtEhFb9O-fo2NpWscqGDK1yrcG58sM7EBJiCs', 6453, 'jwt1', '2017-07-16 17:13:21.736318+02');
INSERT INTO token (cod_token, header, payload, token, "ID", cod_type, date) VALUES ('9a8b56f2-93ce-494f-b0c6-9a98fd288563', '{"alg": "HS256", "typ": "JWT"}', '{"aud": "Service Providers using EasySPID API", "exp": 1500219333, "iat": 1500218133, "iss": "EasySPID gateway", "jti": "9a8b56f2-93ce-494f-b0c6-9a98fd288563", "nbf": 1500218133, "sub": "Access to EasySPID API"}', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDAyMTkzMzMsImlhdCI6MTUwMDIxODEzMywiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6IjlhOGI1NmYyLTkzY2UtNDk0Zi1iMGM2LTlhOThmZDI4ODU2MyIsIm5iZiI6MTUwMDIxODEzMywic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.tbR-bb8pZlRYAj_OJELtDYufAukQa_0_ZaIpR3nhoow', 6454, 'jwt1', '2017-07-16 17:15:32.888074+02');
INSERT INTO token (cod_token, header, payload, token, "ID", cod_type, date) VALUES ('214447cd-1fcc-4f61-952a-a388d0828c72', '{"alg": "HS256", "typ": "JWT"}', '{"aud": "Service Providers using EasySPID API", "exp": 1500219391, "iat": 1500218191, "iss": "EasySPID gateway", "jti": "214447cd-1fcc-4f61-952a-a388d0828c72", "nbf": 1500218191, "sub": "Access to EasySPID API"}', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDAyMTkzOTEsImlhdCI6MTUwMDIxODE5MSwiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6IjIxNDQ0N2NkLTFmY2MtNGY2MS05NTJhLWEzODhkMDgyOGM3MiIsIm5iZiI6MTUwMDIxODE5MSwic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.bs-QsObOocYRx3pWGiTyiMnACjJFO5KST8jC8xwULr4', 6455, 'jwt1', '2017-07-16 17:16:31.261141+02');
INSERT INTO token (cod_token, header, payload, token, "ID", cod_type, date) VALUES ('11a68aab-cd26-46a4-9f07-e8afd6f8a716', '{"alg": "HS256", "typ": "JWT"}', '{"aud": "Service Providers using EasySPID API", "exp": 1500219702, "iat": 1500218502, "iss": "EasySPID gateway", "jti": "11a68aab-cd26-46a4-9f07-e8afd6f8a716", "nbf": 1500218502, "sub": "Access to EasySPID API"}', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDAyMTk3MDIsImlhdCI6MTUwMDIxODUwMiwiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6IjExYTY4YWFiLWNkMjYtNDZhNC05ZjA3LWU4YWZkNmY4YTcxNiIsIm5iZiI6MTUwMDIxODUwMiwic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.V5a8-pC3hiEEtm43DNrVvT2JSQJNOANxj7JwJd0VY4E', 6456, 'jwt1', '2017-07-16 17:21:42.361978+02');
INSERT INTO token (cod_token, header, payload, token, "ID", cod_type, date) VALUES ('6e58ca17-f807-4293-b515-1cfc1f155904', '{"alg": "HS256", "typ": "JWT"}', '{"aud": "Service Providers using EasySPID API", "exp": 1500219753, "iat": 1500218553, "iss": "EasySPID gateway", "jti": "6e58ca17-f807-4293-b515-1cfc1f155904", "nbf": 1500218553, "sub": "Access to EasySPID API"}', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDAyMTk3NTMsImlhdCI6MTUwMDIxODU1MywiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6IjZlNThjYTE3LWY4MDctNDI5My1iNTE1LTFjZmMxZjE1NTkwNCIsIm5iZiI6MTUwMDIxODU1Mywic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.4eD7WzL35uMI93eJuWKxbNfhMnxAAJn3YkTxgjrij8s', 6457, 'jwt1', '2017-07-16 17:22:33.145856+02');
INSERT INTO token (cod_token, header, payload, token, "ID", cod_type, date) VALUES ('7c0ad519-7051-4985-8752-9f312baaa4a6', '{"alg": "HS256", "typ": "JWT"}', '{"aud": "Service Providers using EasySPID API", "exp": 1500221376, "iat": 1500220176, "iss": "EasySPID gateway", "jti": "7c0ad519-7051-4985-8752-9f312baaa4a6", "nbf": 1500220176, "sub": "Access to EasySPID API"}', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDAyMjEzNzYsImlhdCI6MTUwMDIyMDE3NiwiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6IjdjMGFkNTE5LTcwNTEtNDk4NS04NzUyLTlmMzEyYmFhYTRhNiIsIm5iZiI6MTUwMDIyMDE3Niwic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.DHPFiFdo2j8UOXyzDanPrWDDezPDBblXHIr00mK8Iyo', 6458, 'jwt1', '2017-07-16 17:49:36.324661+02');
INSERT INTO token (cod_token, header, payload, token, "ID", cod_type, date) VALUES ('28f52cd0-726c-476d-bdf0-2a29cbebf4c1', '{"alg": "HS256", "typ": "JWT"}', '{"aud": "Service Providers using EasySPID API", "exp": 1500221437, "iat": 1500220237, "iss": "EasySPID gateway", "jti": "28f52cd0-726c-476d-bdf0-2a29cbebf4c1", "nbf": 1500220237, "sub": "Access to EasySPID API"}', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDAyMjE0MzcsImlhdCI6MTUwMDIyMDIzNywiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6IjI4ZjUyY2QwLTcyNmMtNDc2ZC1iZGYwLTJhMjljYmViZjRjMSIsIm5iZiI6MTUwMDIyMDIzNywic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.cPwWVvg1FvhnxSumWRArSttmNOSPT6sH_yZpIt2_ukc', 6459, 'jwt1', '2017-07-16 17:50:36.857979+02');
INSERT INTO token (cod_token, header, payload, token, "ID", cod_type, date) VALUES ('f9b61bb5-32fb-4f59-a0bb-899027f85489', '{"alg": "HS256", "typ": "JWT"}', '{"aud": "Service Providers using EasySPID API", "exp": 1500221491, "iat": 1500220291, "iss": "EasySPID gateway", "jti": "f9b61bb5-32fb-4f59-a0bb-899027f85489", "nbf": 1500220291, "sub": "Access to EasySPID API"}', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDAyMjE0OTEsImlhdCI6MTUwMDIyMDI5MSwiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6ImY5YjYxYmI1LTMyZmItNGY1OS1hMGJiLTg5OTAyN2Y4NTQ4OSIsIm5iZiI6MTUwMDIyMDI5MSwic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.YPSpgEQ6dUYH1t3oAxeq39qa-NCCwZ6ZjOQEI_ZCxcQ', 6460, 'jwt2', '2017-07-16 17:51:30.819616+02');
INSERT INTO token (cod_token, header, payload, token, "ID", cod_type, date) VALUES ('e3ae0353-0be3-4d3e-9878-47392442116a', '{"alg": "HS256", "typ": "JWT"}', '{"aud": "Service Providers using EasySPID API", "exp": 1500244426, "iat": 1500243226, "iss": "EasySPID gateway", "jti": "e3ae0353-0be3-4d3e-9878-47392442116a", "nbf": 1500243226, "sub": "Access to EasySPID API"}', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDAyNDQ0MjYsImlhdCI6MTUwMDI0MzIyNiwiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6ImUzYWUwMzUzLTBiZTMtNGQzZS05ODc4LTQ3MzkyNDQyMTE2YSIsIm5iZiI6MTUwMDI0MzIyNiwic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.TpTgNeJjFKTG35nqMpMLcbxkI__jiP47jGglAISYA4I', 6500, 'jwt2', '2017-07-17 00:13:45.869189+02');
INSERT INTO token (cod_token, header, payload, token, "ID", cod_type, date) VALUES ('861c751e-c42d-4e4b-ae92-25de20cd4ba4', '{"alg": "HS256", "typ": "JWT"}', '{"aud": "Service Providers using EasySPID API", "exp": 1500244532, "iat": 1500243332, "iss": "EasySPID gateway", "jti": "861c751e-c42d-4e4b-ae92-25de20cd4ba4", "nbf": 1500243332, "sub": "Access to EasySPID API"}', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDAyNDQ1MzIsImlhdCI6MTUwMDI0MzMzMiwiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6Ijg2MWM3NTFlLWM0MmQtNGU0Yi1hZTkyLTI1ZGUyMGNkNGJhNCIsIm5iZiI6MTUwMDI0MzMzMiwic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.9DzjkGvQj_y5r-vfjIQp44OPhn83hrn2IiyRALGkdn0', 6501, 'jwt2', '2017-07-17 00:15:31.54878+02');
INSERT INTO token (cod_token, header, payload, token, "ID", cod_type, date) VALUES ('9619d9fe-d12f-4960-b31a-3e84fb51f0d3', '{"alg": "HS256", "typ": "JWT"}', '{"aud": "Service Providers using EasySPID API", "exp": 1500244689, "iat": 1500243489, "iss": "EasySPID gateway", "jti": "9619d9fe-d12f-4960-b31a-3e84fb51f0d3", "nbf": 1500243489, "sub": "Access to EasySPID API"}', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDAyNDQ2ODksImlhdCI6MTUwMDI0MzQ4OSwiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6Ijk2MTlkOWZlLWQxMmYtNDk2MC1iMzFhLTNlODRmYjUxZjBkMyIsIm5iZiI6MTUwMDI0MzQ4OSwic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.uYSjCiVZ2lrX4jdHEBEbBuVBFl88kN4TIwftlpNFXZM', 6502, 'jwt2', '2017-07-17 00:18:09.302823+02');
INSERT INTO token (cod_token, header, payload, token, "ID", cod_type, date) VALUES ('5bb05d1d-05c3-472e-b2d3-3ed0704432c3', '{"alg": "HS256", "typ": "JWT"}', '{"aud": "Service Providers using EasySPID API", "exp": 1500245360, "iat": 1500244160, "iss": "EasySPID gateway", "jti": "5bb05d1d-05c3-472e-b2d3-3ed0704432c3", "nbf": 1500244160, "sub": "Access to EasySPID API"}', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDAyNDUzNjAsImlhdCI6MTUwMDI0NDE2MCwiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6IjViYjA1ZDFkLTA1YzMtNDcyZS1iMmQzLTNlZDA3MDQ0MzJjMyIsIm5iZiI6MTUwMDI0NDE2MCwic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.p1OfEbVQmihv415-G-g65Ki9Q-xaeGHllg5FN5gYj3k', 6503, 'jwt2', '2017-07-17 00:29:19.59448+02');
INSERT INTO token (cod_token, header, payload, token, "ID", cod_type, date) VALUES ('b4d79785-9b5e-483e-a7c0-c19d6e48f153', '{"alg": "HS256", "typ": "JWT"}', '{"aud": "Service Providers using EasySPID API", "exp": 1500245414, "iat": 1500244214, "iss": "EasySPID gateway", "jti": "b4d79785-9b5e-483e-a7c0-c19d6e48f153", "nbf": 1500244214, "sub": "Access to EasySPID API"}', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDAyNDU0MTQsImlhdCI6MTUwMDI0NDIxNCwiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6ImI0ZDc5Nzg1LTliNWUtNDgzZS1hN2MwLWMxOWQ2ZTQ4ZjE1MyIsIm5iZiI6MTUwMDI0NDIxNCwic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.bPw94yqsXkcP45y0IAoQWBiqgTFF7yFHXlysuo0iau4', 6504, 'jwt2', '2017-07-17 00:30:14.153285+02');
INSERT INTO token (cod_token, header, payload, token, "ID", cod_type, date) VALUES ('7886355f-5070-448b-8dd4-ffa02942a7a0', '{"alg": "HS256", "typ": "JWT"}', '{"aud": "Service Providers using EasySPID API", "exp": 1500245414, "iat": 1500244214, "iss": "EasySPID gateway", "jti": "7886355f-5070-448b-8dd4-ffa02942a7a0", "nbf": 1500244214, "sub": "Access to EasySPID API"}', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDAyNDU0MTQsImlhdCI6MTUwMDI0NDIxNCwiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6Ijc4ODYzNTVmLTUwNzAtNDQ4Yi04ZGQ0LWZmYTAyOTQyYTdhMCIsIm5iZiI6MTUwMDI0NDIxNCwic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.okpQ4lgvw6Kkcz9DlFP_9wmGz_33L6KqXCDuEPeoNh8', 6505, 'jwt2', '2017-07-17 00:30:14.194888+02');
INSERT INTO token (cod_token, header, payload, token, "ID", cod_type, date) VALUES ('3954f8bc-0d58-4e17-b9fe-0f0d8bb8fe5d', '{"alg": "HS256", "typ": "JWT"}', '{"aud": "Service Providers using EasySPID API", "exp": 1500245452, "iat": 1500244252, "iss": "EasySPID gateway", "jti": "3954f8bc-0d58-4e17-b9fe-0f0d8bb8fe5d", "nbf": 1500244252, "sub": "Access to EasySPID API"}', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDAyNDU0NTIsImlhdCI6MTUwMDI0NDI1MiwiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6IjM5NTRmOGJjLTBkNTgtNGUxNy1iOWZlLTBmMGQ4YmI4ZmU1ZCIsIm5iZiI6MTUwMDI0NDI1Miwic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.e_dfiB_1CYd_vBigCDoEg9RvJPvBRJlkSP0yB12qtxA', 6506, 'jwt2', '2017-07-17 00:30:51.976084+02');
INSERT INTO token (cod_token, header, payload, token, "ID", cod_type, date) VALUES ('fda84a2a-f86c-4852-9300-888b21825781', '{"alg": "HS256", "typ": "JWT"}', '{"aud": "Service Providers using EasySPID API", "exp": 1500245453, "iat": 1500244253, "iss": "EasySPID gateway", "jti": "fda84a2a-f86c-4852-9300-888b21825781", "nbf": 1500244253, "sub": "Access to EasySPID API"}', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDAyNDU0NTMsImlhdCI6MTUwMDI0NDI1MywiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6ImZkYTg0YTJhLWY4NmMtNDg1Mi05MzAwLTg4OGIyMTgyNTc4MSIsIm5iZiI6MTUwMDI0NDI1Mywic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.Vuiyis0qp7FuwCtJX8D20YYnp8iQb_6PCeDsWoFzyoE', 6507, 'jwt2', '2017-07-17 00:30:52.75982+02');
INSERT INTO token (cod_token, header, payload, token, "ID", cod_type, date) VALUES ('43038ab6-0b84-49b5-850e-2a4d7ffdfe8f', '{"alg": "HS256", "typ": "JWT"}', '{"aud": "Service Providers using EasySPID API", "exp": 1500245772, "iat": 1500244572, "iss": "EasySPID gateway", "jti": "43038ab6-0b84-49b5-850e-2a4d7ffdfe8f", "nbf": 1500244572, "sub": "Access to EasySPID API"}', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDAyNDU3NzIsImlhdCI6MTUwMDI0NDU3MiwiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6IjQzMDM4YWI2LTBiODQtNDliNS04NTBlLTJhNGQ3ZmZkZmU4ZiIsIm5iZiI6MTUwMDI0NDU3Miwic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.UQg3lRBbiHu1OU_sI-3FTIozfe1SFxM5dc4QeIuD38g', 6508, 'jwt2', '2017-07-17 00:36:12.114636+02');
INSERT INTO token (cod_token, header, payload, token, "ID", cod_type, date) VALUES ('1004e8c1-358b-4380-a640-39e069c10d40', '{"alg": "HS256", "typ": "JWT"}', '{"aud": "Service Providers using EasySPID API", "exp": 1500245773, "iat": 1500244573, "iss": "EasySPID gateway", "jti": "1004e8c1-358b-4380-a640-39e069c10d40", "nbf": 1500244573, "sub": "Access to EasySPID API"}', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDAyNDU3NzMsImlhdCI6MTUwMDI0NDU3MywiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6IjEwMDRlOGMxLTM1OGItNDM4MC1hNjQwLTM5ZTA2OWMxMGQ0MCIsIm5iZiI6MTUwMDI0NDU3Mywic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.ojrz1HtZvH6m8ZYW7cUTVDPSP8KMJmhVuoCwnMy_ow0', 6509, 'jwt2', '2017-07-17 00:36:12.598603+02');
INSERT INTO token (cod_token, header, payload, token, "ID", cod_type, date) VALUES ('2b08845d-3687-4fae-bccd-7191119a95e9', '{"alg": "HS256", "typ": "JWT"}', '{"aud": "Service Providers using EasySPID API", "exp": 1500246289, "iat": 1500245089, "iss": "EasySPID gateway", "jti": "2b08845d-3687-4fae-bccd-7191119a95e9", "nbf": 1500245089, "sub": "Access to EasySPID API"}', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDAyNDYyODksImlhdCI6MTUwMDI0NTA4OSwiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6IjJiMDg4NDVkLTM2ODctNGZhZS1iY2NkLTcxOTExMTlhOTVlOSIsIm5iZiI6MTUwMDI0NTA4OSwic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.r9RvgGu2gFGLOViBKY3MUjRYbwXt1mIb67Hd3WE55Zw', 6510, 'jwt1', '2017-07-17 00:44:49.399708+02');
INSERT INTO token (cod_token, header, payload, token, "ID", cod_type, date) VALUES ('376535fb-8266-4912-be0f-03a50714b38d', '{"alg": "HS256", "typ": "JWT"}', '{"aud": "Service Providers using EasySPID API", "exp": 1500246363, "iat": 1500245163, "iss": "EasySPID gateway", "jti": "376535fb-8266-4912-be0f-03a50714b38d", "nbf": 1500245163, "sub": "Access to EasySPID API"}', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDAyNDYzNjMsImlhdCI6MTUwMDI0NTE2MywiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6IjM3NjUzNWZiLTgyNjYtNDkxMi1iZTBmLTAzYTUwNzE0YjM4ZCIsIm5iZiI6MTUwMDI0NTE2Mywic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.gYPCMkuB2_xJ0KUKqyRFyoBPVPGmJ7ZIgtrA918WqOs', 6511, 'jwt1', '2017-07-17 00:46:03.420508+02');
INSERT INTO token (cod_token, header, payload, token, "ID", cod_type, date) VALUES ('b5677067-a335-4bb6-9d98-00fc0c9af57a', '{"alg": "HS256", "typ": "JWT"}', '{"aud": "Service Providers using EasySPID API", "exp": 1500975231, "iat": 1500974031, "iss": "EasySPID gateway", "jti": "b5677067-a335-4bb6-9d98-00fc0c9af57a", "nbf": 1500974031, "sub": "Access to EasySPID API"}', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDA5NzUyMzEsImlhdCI6MTUwMDk3NDAzMSwiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6ImI1Njc3MDY3LWEzMzUtNGJiNi05ZDk4LTAwZmMwYzlhZjU3YSIsIm5iZiI6MTUwMDk3NDAzMSwic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.Gt2Jftdh1i-b0jG5R6j48wdyk_ovNUjKY5wBYZ3Dw_k', 6512, 'jwt1', '2017-07-25 11:13:51.457232+02');
INSERT INTO token (cod_token, header, payload, token, "ID", cod_type, date) VALUES ('43b8533f-ebd6-45d4-82ba-5270c18b02d7', '{"alg": "HS256", "typ": "JWT"}', '{"aud": "Service Providers using EasySPID API", "exp": 1500975371, "iat": 1500974171, "iss": "EasySPID gateway", "jti": "43b8533f-ebd6-45d4-82ba-5270c18b02d7", "nbf": 1500974171, "sub": "Access to EasySPID API"}', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDA5NzUzNzEsImlhdCI6MTUwMDk3NDE3MSwiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6IjQzYjg1MzNmLWViZDYtNDVkNC04MmJhLTUyNzBjMThiMDJkNyIsIm5iZiI6MTUwMDk3NDE3MSwic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.VCMwYRtWei9ARabk0qMbzyn_zSP_XEocEcBuaHw9Enc', 6513, 'jwt1', '2017-07-25 11:16:10.603616+02');


--
-- TOC entry 2859 (class 0 OID 0)
-- Dependencies: 191
-- Name: token_ID_seq; Type: SEQUENCE SET; Schema: jwt; Owner: easyspid
--

SELECT pg_catalog.setval('"token_ID_seq"', 6513, true);


--
-- TOC entry 2804 (class 0 OID 32887)
-- Dependencies: 200
-- Data for Name: token_payload; Type: TABLE DATA; Schema: jwt; Owner: easyspid
--

INSERT INTO token_payload ("ID", cod_payload, cod_type, payload) VALUES (1, 'a42eb51b-1d38-4a28-b544-d730ae97f6fd', 'jwt1', '{"aud": "Service Providers using EasySPID API", "exp": 1, "iat": 1, "iss": "EasySPID gateway", "jti": "1", "nbf": 1, "sub": "Access to EasySPID API"}');
INSERT INTO token_payload ("ID", cod_payload, cod_type, payload) VALUES (5, '38a08350-becf-4816-9177-703c77a47b44', 'jwt1_es256', '{"aud": "Service Providers validating SAML assertions", "exp": 1, "iat": 1, "iss": "EasySPID gateway", "jti": "1", "nbf": 1, "sub": "Validate SAML assertions returned from EasySPID", "saml_id": "_4d38c302617b5bf98951e65b4cf304711e2166df20"}');
INSERT INTO token_payload ("ID", cod_payload, cod_type, payload) VALUES (6, '7381d502-b6c3-4198-9347-c92cdf1fc505', 'jwt2', '{"aud": "Service Providers using EasySPID API", "exp": 1, "iat": 1, "iss": "EasySPID gateway", "jti": "1", "nbf": 1, "sub": "Access to EasySPID API"}');


--
-- TOC entry 2860 (class 0 OID 0)
-- Dependencies: 199
-- Name: token_payload_ID_seq; Type: SEQUENCE SET; Schema: jwt; Owner: easyspid
--

SELECT pg_catalog.setval('"token_payload_ID_seq"', 6, true);


--
-- TOC entry 2798 (class 0 OID 24605)
-- Dependencies: 194
-- Data for Name: token_schemas; Type: TABLE DATA; Schema: jwt; Owner: easyspid
--

INSERT INTO token_schemas ("ID", cod_schema, schema, active, note, cod_type, part) VALUES (1, 'b12d640d-6492-4168-bc55-b80fd72f1593', '{"id": "http://jsonschema.net", "type": "object", "$schema": "http://json-schema.org/draft-04/schema#", "required": ["typ", "alg"], "properties": {"alg": {"id": "http://jsonschema.net/alg", "type": "string", "pattern": "^HS256$", "minLength": 1}, "typ": {"id": "http://jsonschema.net/typ", "type": "string", "pattern": "^JWT$", "minLength": 1}}, "additionalProperties": true}', true, 'JWT header schema', 'jwt1', 'header');
INSERT INTO token_schemas ("ID", cod_schema, schema, active, note, cod_type, part) VALUES (10, 'a697e4d3-9916-468e-9ae6-887cc8095abf', '{"id": "http://jsonschema.net", "type": "object", "$schema": "http://json-schema.org/draft-04/schema#", "required": ["typ", "alg"], "properties": {"alg": {"id": "http://jsonschema.net/alg", "type": "string", "pattern": "^ES256$", "minLength": 1}, "typ": {"id": "http://jsonschema.net/typ", "type": "string", "pattern": "^JWT$", "minLength": 1}}, "additionalProperties": true}', true, 'JWT header schema', 'jwt1_es256', 'header');
INSERT INTO token_schemas ("ID", cod_schema, schema, active, note, cod_type, part) VALUES (11, 'e9dc2991-dd74-4c25-be76-c29ec8174b1e', '{"id": "http://jsonschema.net", "type": "object", "$schema": "http://json-schema.org/draft-04/schema#", "required": ["iss", "aud", "exp", "nbf", "iat"], "properties": {"aud": {"id": "http://jsonschema.net/aud", "type": "string", "pattern": "^Service Providers validating SAML assertions$", "minLength": 1, "description": "Identifies the recipients that the JWT is intended for"}, "exp": {"id": "http://jsonschema.net/exp", "type": "integer", "minimum": 1, "description": "Identifies the expiration time on or after which the JWT MUST NOT be accepted for processing"}, "iat": {"id": "http://jsonschema.net/iat", "type": "integer", "minimum": 1, "description": "Identifies the time at which the JWT was issued"}, "iss": {"id": "http://jsonschema.net/iss", "type": "string", "pattern": "^EasySPID gateway$", "minLength": 1, "description": "Identifies the principal that issued the JWT.  The processing of this claim is generally application specific"}, "jti": {"id": "http://jsonschema.net/jti", "type": "string", "minLength": 1, "description": "Provides a unique identifier for the JWT"}, "nbf": {"id": "http://jsonschema.net/nbf", "type": "integer", "minimum": 1, "description": "Identifies the time before which the JWT MUST NOT be accepted for processing"}, "sub": {"id": "http://jsonschema.net/sub", "type": "string", "pattern": "^Validate SAML assertions returned from EasySPID$", "minLength": 1, "description": "Identifies the principal that is the subject of the JWT"}}, "additionalProperties": true}', true, 'JWT payload schema', 'jwt1_es256', 'payload');
INSERT INTO token_schemas ("ID", cod_schema, schema, active, note, cod_type, part) VALUES (3, '10253bf0-ea39-44f1-bbed-0cdd998aef8c', '{"id": "http://jsonschema.net", "type": "object", "$schema": "http://json-schema.org/draft-04/schema#", "required": ["iss", "aud", "exp", "nbf", "iat"], "properties": {"aud": {"id": "http://jsonschema.net/aud", "type": "string", "pattern": "^Service Providers using EasySPID API$", "minLength": 1, "description": "Identifies the recipients that the JWT is intended for"}, "exp": {"id": "http://jsonschema.net/exp", "type": "integer", "minimum": 1, "description": "Identifies the expiration time on or after which the JWT MUST NOT be accepted for processing"}, "iat": {"id": "http://jsonschema.net/iat", "type": "integer", "minimum": 1, "description": "Identifies the time at which the JWT was issued"}, "iss": {"id": "http://jsonschema.net/iss", "type": "string", "pattern": "^EasySPID gateway$", "minLength": 1, "description": "Identifies the principal that issued the JWT.  The processing of this claim is generally application specific"}, "jti": {"id": "http://jsonschema.net/jti", "type": "string", "minLength": 1, "description": "Provides a unique identifier for the JWT"}, "nbf": {"id": "http://jsonschema.net/nbf", "type": "integer", "minimum": 1, "description": "Identifies the time before which the JWT MUST NOT be accepted for processing"}, "sub": {"id": "http://jsonschema.net/sub", "type": "string", "pattern": "^Access to EasySPID API$", "minLength": 1, "description": "Identifies the principal that is the subject of the JWT"}}, "additionalProperties": true}', true, 'JWT payload schema', 'jwt1', 'payload');
INSERT INTO token_schemas ("ID", cod_schema, schema, active, note, cod_type, part) VALUES (16, '85ff4c17-d059-4d62-9c55-2e36d15a14de', '{"id": "http://jsonschema.net", "type": "object", "$schema": "http://json-schema.org/draft-04/schema#", "required": ["typ", "alg"], "properties": {"alg": {"id": "http://jsonschema.net/alg", "type": "string", "pattern": "^HS256$", "minLength": 1}, "typ": {"id": "http://jsonschema.net/typ", "type": "string", "pattern": "^JWT$", "minLength": 1}}, "additionalProperties": true}', true, 'JWT header schema', 'jwt2', 'header');
INSERT INTO token_schemas ("ID", cod_schema, schema, active, note, cod_type, part) VALUES (17, '12fc974b-34ad-4371-8d15-9443f7b5c0ee', '{"id": "http://jsonschema.net", "type": "object", "$schema": "http://json-schema.org/draft-04/schema#", "required": ["iss", "aud", "exp", "nbf", "iat"], "properties": {"aud": {"id": "http://jsonschema.net/aud", "type": "string", "pattern": "^Service Providers using EasySPID API$", "minLength": 1, "description": "Identifies the recipients that the JWT is intended for"}, "exp": {"id": "http://jsonschema.net/exp", "type": "integer", "minimum": 1, "description": "Identifies the expiration time on or after which the JWT MUST NOT be accepted for processing"}, "iat": {"id": "http://jsonschema.net/iat", "type": "integer", "minimum": 1, "description": "Identifies the time at which the JWT was issued"}, "iss": {"id": "http://jsonschema.net/iss", "type": "string", "pattern": "^EasySPID gateway$", "minLength": 1, "description": "Identifies the principal that issued the JWT.  The processing of this claim is generally application specific"}, "jti": {"id": "http://jsonschema.net/jti", "type": "string", "minLength": 1, "description": "Provides a unique identifier for the JWT"}, "nbf": {"id": "http://jsonschema.net/nbf", "type": "integer", "minimum": 1, "description": "Identifies the time before which the JWT MUST NOT be accepted for processing"}, "sub": {"id": "http://jsonschema.net/sub", "type": "string", "pattern": "^Access to EasySPID API$", "minLength": 1, "description": "Identifies the principal that is the subject of the JWT"}}, "additionalProperties": true}', true, 'JWT payload schema', 'jwt2', 'payload');


--
-- TOC entry 2861 (class 0 OID 0)
-- Dependencies: 193
-- Name: token_schemas_ID_seq; Type: SEQUENCE SET; Schema: jwt; Owner: easyspid
--

SELECT pg_catalog.setval('"token_schemas_ID_seq"', 17, true);


--
-- TOC entry 2802 (class 0 OID 32805)
-- Dependencies: 198
-- Data for Name: token_signature; Type: TABLE DATA; Schema: jwt; Owner: easyspid
--

INSERT INTO token_signature ("ID", cod_signature, key, cod_type, validity, header, pubkey) VALUES (3, '170a8c3f-6126-4851-b51b-e6cafaa1dfcc', 'bellapetutti', 'jwt1', 1200, '{"alg": "HS256", "typ": "JWT"}', 'bellapetutti');
INSERT INTO token_signature ("ID", cod_signature, key, cod_type, validity, header, pubkey) VALUES (8, 'c6e32fe0-f8c0-4ad3-9cf6-9d34d7f5a4a0', '-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIOWEAWdxnv0jrt40DGbTFzuv6SpdxsKH3vWKNmdfvH1IoAcGBSuBBAAK
oUQDQgAEt2i7jE1JiK0lOWE8i8Z6YW0OB9t0vo3OXuQoEmVQepzaP5rJp0dH1hcO
nlk7SqGLLCr33p20G7FxBU6M+hrwug==
-----END EC PRIVATE KEY-----', 'jwt1_es256', 1200, '{"alg": "ES256", "typ": "JWT"}', '-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEt2i7jE1JiK0lOWE8i8Z6YW0OB9t0vo3O
XuQoEmVQepzaP5rJp0dH1hcOnlk7SqGLLCr33p20G7FxBU6M+hrwug==
-----END PUBLIC KEY-----');
INSERT INTO token_signature ("ID", cod_signature, key, cod_type, validity, header, pubkey) VALUES (18, '00a94c0c-90d2-4836-8311-f9cacc1991f0', 'easyspid', 'jwt2', 1200, '{"alg": "HS256", "typ": "JWT"}', 'easyspid');


--
-- TOC entry 2862 (class 0 OID 0)
-- Dependencies: 197
-- Name: token_signature_ID_seq; Type: SEQUENCE SET; Schema: jwt; Owner: easyspid
--

SELECT pg_catalog.setval('"token_signature_ID_seq"', 18, true);


--
-- TOC entry 2800 (class 0 OID 32791)
-- Dependencies: 196
-- Data for Name: token_type; Type: TABLE DATA; Schema: jwt; Owner: easyspid
--

INSERT INTO token_type ("ID", cod_type, note) VALUES (1, 'jwt1', 'Default jwt type');
INSERT INTO token_type ("ID", cod_type, note) VALUES (4, 'jwt1_es256', 'jwt ECDSA 256 asymmetric keys');
INSERT INTO token_type ("ID", cod_type, note) VALUES (6, 'jwt2', 'Generic saml assertions token');


--
-- TOC entry 2863 (class 0 OID 0)
-- Dependencies: 195
-- Name: token_type_ID_seq; Type: SEQUENCE SET; Schema: jwt; Owner: easyspid
--

SELECT pg_catalog.setval('"token_type_ID_seq"', 6, true);


SET search_path = log, pg_catalog;

--
-- TOC entry 2864 (class 0 OID 0)
-- Dependencies: 220
-- Name: request_ID_seq; Type: SEQUENCE SET; Schema: log; Owner: easyspid
--

SELECT pg_catalog.setval('"request_ID_seq"', 86, true);


--
-- TOC entry 2822 (class 0 OID 77209)
-- Dependencies: 221
-- Data for Name: requests; Type: TABLE DATA; Schema: log; Owner: easyspid
--

INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (25, '3dd5851f-20d0-4c1c-b4c0-ffddc6d4f2c4', 'GET', 'http://192.168.56.103:8888/api/prvd', '2017-07-17 00:11:58.16581+02', '192.168.56.1', NULL);
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (26, '7c6ba7cb-ef49-473b-b8b8-5c9a9b61b4d9', 'POST', 'http://192.168.56.103:8888/api/prvd/uniroma1/consume', '2017-07-17 00:15:32.112257+02', '192.168.56.1', 'SAMLResponse=PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8%2BPHNhbWwycDpSZXNwb25zZSB4bWxuczpzYW1sMnA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCIgRGVzdGluYXRpb249Imh0dHA6Ly93d3cudW5pcm9tYTEuaXQvc3BpZC9jb25zdW1lIiBJRD0iX2QzYmI5ODg0LTY2NTctNDhkMS05YWE1LTdiOWQ1ODNiZWE3NyIgSW5SZXNwb25zZVRvPSJfZGJhZjg1YzNlMzQ0NWM0M2ZiODUwN2E5ZjI5ODMxNTkiIElzc3VlSW5zdGFudD0iMjAxNi0wNi0xNlQwODo0MzozMS45ODhaIiBWZXJzaW9uPSIyLjAiPjxzYW1sMjpJc3N1ZXIgeG1sbnM6c2FtbDI9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPmh0dHBzOi8vcG9zdGVpZC5wb3N0ZS5pdDwvc2FtbDI6SXNzdWVyPjxTaWduYXR1cmUgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxTaWduZWRJbmZvPjxDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8%2BPFNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNyc2Etc2hhMSIvPjxSZWZlcmVuY2UgVVJJPSIjX2QzYmI5ODg0LTY2NTctNDhkMS05YWE1LTdiOWQ1ODNiZWE3NyI%2BPFRyYW5zZm9ybXM%2BPFRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8%2BPFRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvVHJhbnNmb3Jtcz48RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3NoYTEiLz48RGlnZXN0VmFsdWU%2BQmdDTFgxZkZOUE51YmU2dE5Fa3V6TzBZdXRJPTwvRGlnZXN0VmFsdWU%2BPC9SZWZlcmVuY2U%2BPC9TaWduZWRJbmZvPjxTaWduYXR1cmVWYWx1ZT5GemRlRzg2dTgvQ1VZY1Mvc2l4OGJydzh3aXhYUHJzRFRLTnJmUmkvM2lSRmlJWmVPZHJMS1lLWHBhSEFmVEhFVVQ0eGw5U1haNVFhDQpiYlRxWkc2M2VhOEtuT0dyYXI2Vm9reWRYVWFUcXpaVk9XK05PWHVWdi80bzJ5TlhoZ2tDdFk2YklNdW5GQUx5ak9IN3RYZVJlZ0srDQpiRWZ4aDRZUGZ0c0Z2RGg4aWg3UTNjaXFyOFJRV2R2VkZCU2hCd0R1R0ZIdE5uaEhzSDhFdWljY0s0V25WTXpLcksvMXFnNWxldDBHDQo0Ym03cklhQk93dTFGRUtDNENYV2U0K00vR2dIR0RMbWpoVnVqeTVZK2hNUENJUitYb2E2OUdHTnNoOTJhUFFlYzVOVlNxVklzT1JjDQpDMkdaZEpuMFV3b2xudDZGaGNGSnNTTjNLem5HYWhQcDRsY0VHQT09PC9TaWduYXR1cmVWYWx1ZT48S2V5SW5mbz48WDUwOURhdGE%2BPFg1MDlDZXJ0aWZpY2F0ZT5NSUlFS3pDQ0F4T2dBd0lCQWdJREUyWTBNQTBHQ1NxR1NJYjNEUUVCQ3dVQU1HQXhDekFKQmdOVkJBWVRBa2xVTVJnd0ZnWURWUVFLDQpEQTlRYjNOMFpXTnZiU0JUTG5BdVFTNHhJREFlQmdOVkJBc01GME5sY25ScFptbGpZWFJwYjI0Z1FYVjBhRzl5YVhSNU1SVXdFd1lEDQpWUVFEREF4UWIzTjBaV052YlNCRFFUTXdIaGNOTVRZd01qSTJNVFUxTWpRMFdoY05NakV3TWpJMk1UVTFNalEwV2pCeE1Rc3dDUVlEDQpWUVFHRXdKSlZERU9NQXdHQTFVRUNBd0ZTWFJoYkhreERUQUxCZ05WQkFjTUJGSnZiV1V4SGpBY0JnTlZCQW9NRlZCdmMzUmxJRWwwDQpZV3hwWVc1bElGTXVjQzVCTGpFTk1Bc0dBMVVFQ3d3RVUxQkpSREVVTUJJR0ExVUVBd3dMU1VSUUxWQnZjM1JsU1VRd2dnRWlNQTBHDQpDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRRFpGRXRKb0VIRkFqcENhWmNqNURWV3JSRHlhTFp5dTMxWEFwc2xibzg3DQpDeVd6NjFPSk10dzZRUVUwTWRDdHJZYnRTSjZ2Snd4Ny82RVVqc1ozdTR4M0VQTGRsa3lpR09xdWtQd0FUdjRjN1RWT1VWczVvbklxDQpUcGhNOWIrQUhSZzRlaGlNR2VzbS85ZDdSSWFMdU43OWlQVXZkTG42V1AzaWRBZkV3K3JoSi93WUVRMGgxWG01b3NOVWd0V2NCR2F2DQpaSWpMc3NXTnJERGZKWXhYSDNRWjBrSTZmZUV2TENKd2dqWExHa0J1aEZlaE5oTTRmaGJYOWlVQ1d3d2tKM0pzUDIrK1JjL2lUQTBMDQpaaGlVc1hOTnE3Z0JjTEFKOVVYMlYxZFdqVHpCSGV2ZkhzcHp0NGUwVmdJSXdiRFJxc1J0RjhWVVBTRFlZYkxvcXdiTHQxOFhBZ01CDQpBQUdqZ2R3d2dka3dSZ1lEVlIwZ0JEOHdQVEF3QmdjclRBc0JBZ0VCTUNVd0l3WUlLd1lCQlFVSEFnRVdGMmgwZEhBNkx5OTNkM2N1DQpjRzl6ZEdWalpYSjBMbWwwTUFrR0J5dE1Dd0VCQ2dJd0RnWURWUjBQQVFIL0JBUURBZ1N3TUI4R0ExVWRJd1FZTUJhQUZLYzBYUDJGDQpCeVlVMmwwZ0Z6R0tFOHpWU3pmbU1EOEdBMVVkSHdRNE1EWXdOS0F5b0RDR0xtaDBkSEE2THk5d2IzTjBaV05sY25RdWNHOXpkR1V1DQphWFF2Y0c5emRHVmpiMjFqWVRNdlkzSnNNeTVqY213d0hRWURWUjBPQkJZRUZFdnJpa1pRa2ZCanVpVHB4RXhTQmU4d0dnc3lNQTBHDQpDU3FHU0liM0RRRUJDd1VBQTRJQkFRQk5BdzhVb2VpQ0YrMXJGczI3ZDNiRWVmNkNMZS9QSmdhOUVmd0tJdGpNREQ5UXpUL0ZTaFJXDQpLTEhsSzY5TUhMMVpMUFJQdnVXVVRrSU9IVHBOcUJQSUx2TzF1MTNiU2crNm8rMk9kcUFrQ0JrYlRxYkdqV1NQTGFUVVZOVjZNYlhtDQp2dHREOFZkOXZJWmcxeEJCRzNGYWkxM2R3dlNqM2hBWmQ4dWc4YThmVzF5L2lEYlJDNUQxTytIbEhEdXZJVzRMYkowOTNqZGorb1p3DQpTeWQyMTZndFhMMDBRQTBDMXVNdUR2OVdmOUl4bmlUYjcxMGRSU2dJY000L2VSNzgzMmZaZ2RPc29hbEZ6R1lXeFNDczhXT1pyanB1DQpiMWZkYVJTRXVDUWsyK2dtZHNpUmNUczlFcVBDQ05pTmxyTkFpV0V5R3RMOEE0YW8zcERNd0N0cmIyeXI8L1g1MDlDZXJ0aWZpY2F0ZT48L1g1MDlEYXRhPjwvS2V5SW5mbz48L1NpZ25hdHVyZT48c2FtbDJwOlN0YXR1cz48c2FtbDJwOlN0YXR1c0NvZGUgVmFsdWU9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6U3VjY2VzcyIvPjwvc2FtbDJwOlN0YXR1cz48c2FtbDI6QXNzZXJ0aW9uIHhtbG5zOnNhbWwyPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0iXzQ2ZTllOTJlLTk2ODItNDBkYy05OTIxLTg4YmE2ZjIzMDhlMyIgSXNzdWVJbnN0YW50PSIyMDE2LTA2LTE2VDA4OjQzOjMwLjk4OVoiIFZlcnNpb249IjIuMCI%2BPHNhbWwyOklzc3VlciBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OmVudGl0eSI%2BaHR0cHM6Ly9wb3N0ZWlkLnBvc3RlLml0PC9zYW1sMjpJc3N1ZXI%2BPFNpZ25hdHVyZSB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI%2BPFNpZ25lZEluZm8%2BPENhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3JzYS1zaGExIi8%2BPFJlZmVyZW5jZSBVUkk9IiNfNDZlOWU5MmUtOTY4Mi00MGRjLTk5MjEtODhiYTZmMjMwOGUzIj48VHJhbnNmb3Jtcz48VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz48VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8%2BPC9UcmFuc2Zvcm1zPjxEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjc2hhMSIvPjxEaWdlc3RWYWx1ZT5xYUlsWGZFaWtlWmw1cXY1ZkZ1YkV3ZVN2OWM9PC9EaWdlc3RWYWx1ZT48L1JlZmVyZW5jZT48L1NpZ25lZEluZm8%2BPFNpZ25hdHVyZVZhbHVlPlNoOXBRMnFFaXd1dThNMGQwd3VwNXAyY3l5ZmkvYWE2VG93UjNTK0RyTTRpTWpIUW1oZVNkeTUweDhOd044SlVDenBqSktlUmt1L1MNCk1NRjF2YjlBcWt5clh4UlJhYTU1VlRNd2xOa0FYbmtEanFIQ3FvanRaci9DQjMxbHU5bEhWcjNQV1M1NC8xL1ZKRTBsdUNUbEl5akENCnV4SzZTQktaWW9mS2hWRThiLzBYTE93Yk1pUVRtZG00eG1yVGk5YVYzT09zeTRpNTNaOUJkUnVnWmxpYldJKys5ZGE5ZzFhMjJoVVgNCmRzdSt6ZGZLcUN3elQ0Q1FUejBZYjBrbGI2cnhqc0VDUC9wekljM0pXSWJGbXU4djcxdk9Na1VTTHlOODV6MzJodVRlQi9JcG9aMTcNCjg0SjlocVh5SFZQeEd1b09VMkgxK1BxNnoyZU1GbGVsMFB3TjlnPT08L1NpZ25hdHVyZVZhbHVlPjxLZXlJbmZvPjxYNTA5RGF0YT48WDUwOUNlcnRpZmljYXRlPk1JSUVLekNDQXhPZ0F3SUJBZ0lERTJZME1BMEdDU3FHU0liM0RRRUJDd1VBTUdBeEN6QUpCZ05WQkFZVEFrbFVNUmd3RmdZRFZRUUsNCkRBOVFiM04wWldOdmJTQlRMbkF1UVM0eElEQWVCZ05WQkFzTUYwTmxjblJwWm1sallYUnBiMjRnUVhWMGFHOXlhWFI1TVJVd0V3WUQNClZRUUREQXhRYjNOMFpXTnZiU0JEUVRNd0hoY05NVFl3TWpJMk1UVTFNalEwV2hjTk1qRXdNakkyTVRVMU1qUTBXakJ4TVFzd0NRWUQNClZRUUdFd0pKVkRFT01Bd0dBMVVFQ0F3RlNYUmhiSGt4RFRBTEJnTlZCQWNNQkZKdmJXVXhIakFjQmdOVkJBb01GVkJ2YzNSbElFbDANCllXeHBZVzVsSUZNdWNDNUJMakVOTUFzR0ExVUVDd3dFVTFCSlJERVVNQklHQTFVRUF3d0xTVVJRTFZCdmMzUmxTVVF3Z2dFaU1BMEcNCkNTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFEWkZFdEpvRUhGQWpwQ2FaY2o1RFZXclJEeWFMWnl1MzFYQXBzbGJvODcNCkN5V3o2MU9KTXR3NlFRVTBNZEN0cllidFNKNnZKd3g3LzZFVWpzWjN1NHgzRVBMZGxreWlHT3F1a1B3QVR2NGM3VFZPVVZzNW9uSXENClRwaE05YitBSFJnNGVoaU1HZXNtLzlkN1JJYUx1Tjc5aVBVdmRMbjZXUDNpZEFmRXcrcmhKL3dZRVEwaDFYbTVvc05VZ3RXY0JHYXYNClpJakxzc1dOckREZkpZeFhIM1FaMGtJNmZlRXZMQ0p3Z2pYTEdrQnVoRmVoTmhNNGZoYlg5aVVDV3d3a0ozSnNQMisrUmMvaVRBMEwNClpoaVVzWE5OcTdnQmNMQUo5VVgyVjFkV2pUekJIZXZmSHNwenQ0ZTBWZ0lJd2JEUnFzUnRGOFZVUFNEWVliTG9xd2JMdDE4WEFnTUINCkFBR2pnZHd3Z2Rrd1JnWURWUjBnQkQ4d1BUQXdCZ2NyVEFzQkFnRUJNQ1V3SXdZSUt3WUJCUVVIQWdFV0YyaDBkSEE2THk5M2QzY3UNCmNHOXpkR1ZqWlhKMExtbDBNQWtHQnl0TUN3RUJDZ0l3RGdZRFZSMFBBUUgvQkFRREFnU3dNQjhHQTFVZEl3UVlNQmFBRktjMFhQMkYNCkJ5WVUybDBnRnpHS0U4elZTemZtTUQ4R0ExVWRId1E0TURZd05LQXlvRENHTG1oMGRIQTZMeTl3YjNOMFpXTmxjblF1Y0c5emRHVXUNCmFYUXZjRzl6ZEdWamIyMWpZVE12WTNKc015NWpjbXd3SFFZRFZSME9CQllFRkV2cmlrWlFrZkJqdWlUcHhFeFNCZTh3R2dzeU1BMEcNCkNTcUdTSWIzRFFFQkN3VUFBNElCQVFCTkF3OFVvZWlDRisxckZzMjdkM2JFZWY2Q0xlL1BKZ2E5RWZ3S0l0ak1ERDlRelQvRlNoUlcNCktMSGxLNjlNSEwxWkxQUlB2dVdVVGtJT0hUcE5xQlBJTHZPMXUxM2JTZys2bysyT2RxQWtDQmtiVHFiR2pXU1BMYVRVVk5WNk1iWG0NCnZ0dEQ4VmQ5dklaZzF4QkJHM0ZhaTEzZHd2U2ozaEFaZDh1ZzhhOGZXMXkvaURiUkM1RDFPK0hsSER1dklXNExiSjA5M2pkaitvWncNClN5ZDIxNmd0WEwwMFFBMEMxdU11RHY5V2Y5SXhuaVRiNzEwZFJTZ0ljTTQvZVI3ODMyZlpnZE9zb2FsRnpHWVd4U0NzOFdPWnJqcHUNCmIxZmRhUlNFdUNRazIrZ21kc2lSY1RzOUVxUENDTmlObHJOQWlXRXlHdEw4QTRhbzNwRE13Q3RyYjJ5cjwvWDUwOUNlcnRpZmljYXRlPjwvWDUwOURhdGE%2BPC9LZXlJbmZvPjwvU2lnbmF0dXJlPjxzYW1sMjpTdWJqZWN0PjxzYW1sMjpOYW1lSUQgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6bmFtZWlkLWZvcm1hdDp0cmFuc2llbnQiIE5hbWVRdWFsaWZpZXI9Imh0dHBzOi8vcG9zdGVpZC5wb3N0ZS5pdCI%2BU1BJRC02NDBmOWNmNC04ZjE2LTRkN2YtODhmNi05MThhZGI1ZjBlMDE8L3NhbWwyOk5hbWVJRD48c2FtbDI6U3ViamVjdENvbmZpcm1hdGlvbiBNZXRob2Q9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpjbTpiZWFyZXIiPjxzYW1sMjpTdWJqZWN0Q29uZmlybWF0aW9uRGF0YSBJblJlc3BvbnNlVG89Il9kYmFmODVjM2UzNDQ1YzQzZmI4NTA3YTlmMjk4MzE1OSIgTm90T25PckFmdGVyPSIyMDE2LTA2LTE2VDA4OjQ0OjMwLjk4OFoiIFJlY2lwaWVudD0iaHR0cDovL3d3dy51bmlyb21hMS5pdC9zcGlkL2NvbnN1bWUiLz48L3NhbWwyOlN1YmplY3RDb25maXJtYXRpb24%2BPC9zYW1sMjpTdWJqZWN0PjxzYW1sMjpDb25kaXRpb25zIE5vdEJlZm9yZT0iMjAxNi0wNi0xNlQwODo0MzozMC45ODhaIiBOb3RPbk9yQWZ0ZXI9IjIwMTYtMDYtMTZUMDg6NDQ6MzAuOTg4WiI%2BPHNhbWwyOkF1ZGllbmNlUmVzdHJpY3Rpb24%2BPHNhbWwyOkF1ZGllbmNlPmh0dHA6Ly93d3cudW5pcm9tYTEuaXQ8L3NhbWwyOkF1ZGllbmNlPjwvc2FtbDI6QXVkaWVuY2VSZXN0cmljdGlvbj48L3NhbWwyOkNvbmRpdGlvbnM%2BPHNhbWwyOkF1dGhuU3RhdGVtZW50IEF1dGhuSW5zdGFudD0iMjAxNi0wNi0xNlQwODo0MzozMC45ODhaIiBTZXNzaW9uSW5kZXg9ImNGZERObTA3QXUvU2hEZlVzOURmNVAzTkllOXUwZWhIVHQrZEhHMlZuT2VrVUd5SUxQYjRZdz09Ij48c2FtbDI6QXV0aG5Db250ZXh0PjxzYW1sMjpBdXRobkNvbnRleHRDbGFzc1JlZj51cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YWM6Y2xhc3NlczpTcGlkTDE8L3NhbWwyOkF1dGhuQ29udGV4dENsYXNzUmVmPjwvc2FtbDI6QXV0aG5Db250ZXh0Pjwvc2FtbDI6QXV0aG5TdGF0ZW1lbnQ%2BPHNhbWwyOkF0dHJpYnV0ZVN0YXRlbWVudD48c2FtbDI6QXR0cmlidXRlIE5hbWU9ImZpc2NhbE51bWJlciI%2BPHNhbWwyOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI%2BVElOSVQtR0hOTFJUODVBMjFMMjE5UDwvc2FtbDI6QXR0cmlidXRlVmFsdWU%2BPC9zYW1sMjpBdHRyaWJ1dGU%2BPC9zYW1sMjpBdHRyaWJ1dGVTdGF0ZW1lbnQ%2BPC9zYW1sMjpBc3NlcnRpb24%2BPC9zYW1sMnA6UmVzcG9uc2U%2B&RelayState=uniroma1_srelay1');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (27, '94780a9c-5bd7-42a7-82f9-55ca4c4c63ca', 'POST', 'http://192.168.56.103:8888/api/prvd/uniroma1/consume', '2017-07-17 00:29:20.074298+02', '192.168.56.1', 'SAMLResponse=PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8%2BPHNhbWwycDpSZXNwb25zZSB4bWxuczpzYW1sMnA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCIgRGVzdGluYXRpb249Imh0dHA6Ly93d3cudW5pcm9tYTEuaXQvc3BpZC9jb25zdW1lIiBJRD0iX2QzYmI5ODg0LTY2NTctNDhkMS05YWE1LTdiOWQ1ODNiZWE3NyIgSW5SZXNwb25zZVRvPSJfZGJhZjg1YzNlMzQ0NWM0M2ZiODUwN2E5ZjI5ODMxNTkiIElzc3VlSW5zdGFudD0iMjAxNi0wNi0xNlQwODo0MzozMS45ODhaIiBWZXJzaW9uPSIyLjAiPjxzYW1sMjpJc3N1ZXIgeG1sbnM6c2FtbDI9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPmh0dHBzOi8vcG9zdGVpZC5wb3N0ZS5pdDwvc2FtbDI6SXNzdWVyPjxTaWduYXR1cmUgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxTaWduZWRJbmZvPjxDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8%2BPFNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNyc2Etc2hhMSIvPjxSZWZlcmVuY2UgVVJJPSIjX2QzYmI5ODg0LTY2NTctNDhkMS05YWE1LTdiOWQ1ODNiZWE3NyI%2BPFRyYW5zZm9ybXM%2BPFRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8%2BPFRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvVHJhbnNmb3Jtcz48RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3NoYTEiLz48RGlnZXN0VmFsdWU%2BQmdDTFgxZkZOUE51YmU2dE5Fa3V6TzBZdXRJPTwvRGlnZXN0VmFsdWU%2BPC9SZWZlcmVuY2U%2BPC9TaWduZWRJbmZvPjxTaWduYXR1cmVWYWx1ZT5GemRlRzg2dTgvQ1VZY1Mvc2l4OGJydzh3aXhYUHJzRFRLTnJmUmkvM2lSRmlJWmVPZHJMS1lLWHBhSEFmVEhFVVQ0eGw5U1haNVFhDQpiYlRxWkc2M2VhOEtuT0dyYXI2Vm9reWRYVWFUcXpaVk9XK05PWHVWdi80bzJ5TlhoZ2tDdFk2YklNdW5GQUx5ak9IN3RYZVJlZ0srDQpiRWZ4aDRZUGZ0c0Z2RGg4aWg3UTNjaXFyOFJRV2R2VkZCU2hCd0R1R0ZIdE5uaEhzSDhFdWljY0s0V25WTXpLcksvMXFnNWxldDBHDQo0Ym03cklhQk93dTFGRUtDNENYV2U0K00vR2dIR0RMbWpoVnVqeTVZK2hNUENJUitYb2E2OUdHTnNoOTJhUFFlYzVOVlNxVklzT1JjDQpDMkdaZEpuMFV3b2xudDZGaGNGSnNTTjNLem5HYWhQcDRsY0VHQT09PC9TaWduYXR1cmVWYWx1ZT48S2V5SW5mbz48WDUwOURhdGE%2BPFg1MDlDZXJ0aWZpY2F0ZT5NSUlFS3pDQ0F4T2dBd0lCQWdJREUyWTBNQTBHQ1NxR1NJYjNEUUVCQ3dVQU1HQXhDekFKQmdOVkJBWVRBa2xVTVJnd0ZnWURWUVFLDQpEQTlRYjNOMFpXTnZiU0JUTG5BdVFTNHhJREFlQmdOVkJBc01GME5sY25ScFptbGpZWFJwYjI0Z1FYVjBhRzl5YVhSNU1SVXdFd1lEDQpWUVFEREF4UWIzTjBaV052YlNCRFFUTXdIaGNOTVRZd01qSTJNVFUxTWpRMFdoY05NakV3TWpJMk1UVTFNalEwV2pCeE1Rc3dDUVlEDQpWUVFHRXdKSlZERU9NQXdHQTFVRUNBd0ZTWFJoYkhreERUQUxCZ05WQkFjTUJGSnZiV1V4SGpBY0JnTlZCQW9NRlZCdmMzUmxJRWwwDQpZV3hwWVc1bElGTXVjQzVCTGpFTk1Bc0dBMVVFQ3d3RVUxQkpSREVVTUJJR0ExVUVBd3dMU1VSUUxWQnZjM1JsU1VRd2dnRWlNQTBHDQpDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRRFpGRXRKb0VIRkFqcENhWmNqNURWV3JSRHlhTFp5dTMxWEFwc2xibzg3DQpDeVd6NjFPSk10dzZRUVUwTWRDdHJZYnRTSjZ2Snd4Ny82RVVqc1ozdTR4M0VQTGRsa3lpR09xdWtQd0FUdjRjN1RWT1VWczVvbklxDQpUcGhNOWIrQUhSZzRlaGlNR2VzbS85ZDdSSWFMdU43OWlQVXZkTG42V1AzaWRBZkV3K3JoSi93WUVRMGgxWG01b3NOVWd0V2NCR2F2DQpaSWpMc3NXTnJERGZKWXhYSDNRWjBrSTZmZUV2TENKd2dqWExHa0J1aEZlaE5oTTRmaGJYOWlVQ1d3d2tKM0pzUDIrK1JjL2lUQTBMDQpaaGlVc1hOTnE3Z0JjTEFKOVVYMlYxZFdqVHpCSGV2ZkhzcHp0NGUwVmdJSXdiRFJxc1J0RjhWVVBTRFlZYkxvcXdiTHQxOFhBZ01CDQpBQUdqZ2R3d2dka3dSZ1lEVlIwZ0JEOHdQVEF3QmdjclRBc0JBZ0VCTUNVd0l3WUlLd1lCQlFVSEFnRVdGMmgwZEhBNkx5OTNkM2N1DQpjRzl6ZEdWalpYSjBMbWwwTUFrR0J5dE1Dd0VCQ2dJd0RnWURWUjBQQVFIL0JBUURBZ1N3TUI4R0ExVWRJd1FZTUJhQUZLYzBYUDJGDQpCeVlVMmwwZ0Z6R0tFOHpWU3pmbU1EOEdBMVVkSHdRNE1EWXdOS0F5b0RDR0xtaDBkSEE2THk5d2IzTjBaV05sY25RdWNHOXpkR1V1DQphWFF2Y0c5emRHVmpiMjFqWVRNdlkzSnNNeTVqY213d0hRWURWUjBPQkJZRUZFdnJpa1pRa2ZCanVpVHB4RXhTQmU4d0dnc3lNQTBHDQpDU3FHU0liM0RRRUJDd1VBQTRJQkFRQk5BdzhVb2VpQ0YrMXJGczI3ZDNiRWVmNkNMZS9QSmdhOUVmd0tJdGpNREQ5UXpUL0ZTaFJXDQpLTEhsSzY5TUhMMVpMUFJQdnVXVVRrSU9IVHBOcUJQSUx2TzF1MTNiU2crNm8rMk9kcUFrQ0JrYlRxYkdqV1NQTGFUVVZOVjZNYlhtDQp2dHREOFZkOXZJWmcxeEJCRzNGYWkxM2R3dlNqM2hBWmQ4dWc4YThmVzF5L2lEYlJDNUQxTytIbEhEdXZJVzRMYkowOTNqZGorb1p3DQpTeWQyMTZndFhMMDBRQTBDMXVNdUR2OVdmOUl4bmlUYjcxMGRSU2dJY000L2VSNzgzMmZaZ2RPc29hbEZ6R1lXeFNDczhXT1pyanB1DQpiMWZkYVJTRXVDUWsyK2dtZHNpUmNUczlFcVBDQ05pTmxyTkFpV0V5R3RMOEE0YW8zcERNd0N0cmIyeXI8L1g1MDlDZXJ0aWZpY2F0ZT48L1g1MDlEYXRhPjwvS2V5SW5mbz48L1NpZ25hdHVyZT48c2FtbDJwOlN0YXR1cz48c2FtbDJwOlN0YXR1c0NvZGUgVmFsdWU9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6U3VjY2VzcyIvPjwvc2FtbDJwOlN0YXR1cz48c2FtbDI6QXNzZXJ0aW9uIHhtbG5zOnNhbWwyPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0iXzQ2ZTllOTJlLTk2ODItNDBkYy05OTIxLTg4YmE2ZjIzMDhlMyIgSXNzdWVJbnN0YW50PSIyMDE2LTA2LTE2VDA4OjQzOjMwLjk4OVoiIFZlcnNpb249IjIuMCI%2BPHNhbWwyOklzc3VlciBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OmVudGl0eSI%2BaHR0cHM6Ly9wb3N0ZWlkLnBvc3RlLml0PC9zYW1sMjpJc3N1ZXI%2BPFNpZ25hdHVyZSB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI%2BPFNpZ25lZEluZm8%2BPENhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3JzYS1zaGExIi8%2BPFJlZmVyZW5jZSBVUkk9IiNfNDZlOWU5MmUtOTY4Mi00MGRjLTk5MjEtODhiYTZmMjMwOGUzIj48VHJhbnNmb3Jtcz48VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz48VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8%2BPC9UcmFuc2Zvcm1zPjxEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjc2hhMSIvPjxEaWdlc3RWYWx1ZT5xYUlsWGZFaWtlWmw1cXY1ZkZ1YkV3ZVN2OWM9PC9EaWdlc3RWYWx1ZT48L1JlZmVyZW5jZT48L1NpZ25lZEluZm8%2BPFNpZ25hdHVyZVZhbHVlPlNoOXBRMnFFaXd1dThNMGQwd3VwNXAyY3l5ZmkvYWE2VG93UjNTK0RyTTRpTWpIUW1oZVNkeTUweDhOd044SlVDenBqSktlUmt1L1MNCk1NRjF2YjlBcWt5clh4UlJhYTU1VlRNd2xOa0FYbmtEanFIQ3FvanRaci9DQjMxbHU5bEhWcjNQV1M1NC8xL1ZKRTBsdUNUbEl5akENCnV4SzZTQktaWW9mS2hWRThiLzBYTE93Yk1pUVRtZG00eG1yVGk5YVYzT09zeTRpNTNaOUJkUnVnWmxpYldJKys5ZGE5ZzFhMjJoVVgNCmRzdSt6ZGZLcUN3elQ0Q1FUejBZYjBrbGI2cnhqc0VDUC9wekljM0pXSWJGbXU4djcxdk9Na1VTTHlOODV6MzJodVRlQi9JcG9aMTcNCjg0SjlocVh5SFZQeEd1b09VMkgxK1BxNnoyZU1GbGVsMFB3TjlnPT08L1NpZ25hdHVyZVZhbHVlPjxLZXlJbmZvPjxYNTA5RGF0YT48WDUwOUNlcnRpZmljYXRlPk1JSUVLekNDQXhPZ0F3SUJBZ0lERTJZME1BMEdDU3FHU0liM0RRRUJDd1VBTUdBeEN6QUpCZ05WQkFZVEFrbFVNUmd3RmdZRFZRUUsNCkRBOVFiM04wWldOdmJTQlRMbkF1UVM0eElEQWVCZ05WQkFzTUYwTmxjblJwWm1sallYUnBiMjRnUVhWMGFHOXlhWFI1TVJVd0V3WUQNClZRUUREQXhRYjNOMFpXTnZiU0JEUVRNd0hoY05NVFl3TWpJMk1UVTFNalEwV2hjTk1qRXdNakkyTVRVMU1qUTBXakJ4TVFzd0NRWUQNClZRUUdFd0pKVkRFT01Bd0dBMVVFQ0F3RlNYUmhiSGt4RFRBTEJnTlZCQWNNQkZKdmJXVXhIakFjQmdOVkJBb01GVkJ2YzNSbElFbDANCllXeHBZVzVsSUZNdWNDNUJMakVOTUFzR0ExVUVDd3dFVTFCSlJERVVNQklHQTFVRUF3d0xTVVJRTFZCdmMzUmxTVVF3Z2dFaU1BMEcNCkNTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFEWkZFdEpvRUhGQWpwQ2FaY2o1RFZXclJEeWFMWnl1MzFYQXBzbGJvODcNCkN5V3o2MU9KTXR3NlFRVTBNZEN0cllidFNKNnZKd3g3LzZFVWpzWjN1NHgzRVBMZGxreWlHT3F1a1B3QVR2NGM3VFZPVVZzNW9uSXENClRwaE05YitBSFJnNGVoaU1HZXNtLzlkN1JJYUx1Tjc5aVBVdmRMbjZXUDNpZEFmRXcrcmhKL3dZRVEwaDFYbTVvc05VZ3RXY0JHYXYNClpJakxzc1dOckREZkpZeFhIM1FaMGtJNmZlRXZMQ0p3Z2pYTEdrQnVoRmVoTmhNNGZoYlg5aVVDV3d3a0ozSnNQMisrUmMvaVRBMEwNClpoaVVzWE5OcTdnQmNMQUo5VVgyVjFkV2pUekJIZXZmSHNwenQ0ZTBWZ0lJd2JEUnFzUnRGOFZVUFNEWVliTG9xd2JMdDE4WEFnTUINCkFBR2pnZHd3Z2Rrd1JnWURWUjBnQkQ4d1BUQXdCZ2NyVEFzQkFnRUJNQ1V3SXdZSUt3WUJCUVVIQWdFV0YyaDBkSEE2THk5M2QzY3UNCmNHOXpkR1ZqWlhKMExtbDBNQWtHQnl0TUN3RUJDZ0l3RGdZRFZSMFBBUUgvQkFRREFnU3dNQjhHQTFVZEl3UVlNQmFBRktjMFhQMkYNCkJ5WVUybDBnRnpHS0U4elZTemZtTUQ4R0ExVWRId1E0TURZd05LQXlvRENHTG1oMGRIQTZMeTl3YjNOMFpXTmxjblF1Y0c5emRHVXUNCmFYUXZjRzl6ZEdWamIyMWpZVE12WTNKc015NWpjbXd3SFFZRFZSME9CQllFRkV2cmlrWlFrZkJqdWlUcHhFeFNCZTh3R2dzeU1BMEcNCkNTcUdTSWIzRFFFQkN3VUFBNElCQVFCTkF3OFVvZWlDRisxckZzMjdkM2JFZWY2Q0xlL1BKZ2E5RWZ3S0l0ak1ERDlRelQvRlNoUlcNCktMSGxLNjlNSEwxWkxQUlB2dVdVVGtJT0hUcE5xQlBJTHZPMXUxM2JTZys2bysyT2RxQWtDQmtiVHFiR2pXU1BMYVRVVk5WNk1iWG0NCnZ0dEQ4VmQ5dklaZzF4QkJHM0ZhaTEzZHd2U2ozaEFaZDh1ZzhhOGZXMXkvaURiUkM1RDFPK0hsSER1dklXNExiSjA5M2pkaitvWncNClN5ZDIxNmd0WEwwMFFBMEMxdU11RHY5V2Y5SXhuaVRiNzEwZFJTZ0ljTTQvZVI3ODMyZlpnZE9zb2FsRnpHWVd4U0NzOFdPWnJqcHUNCmIxZmRhUlNFdUNRazIrZ21kc2lSY1RzOUVxUENDTmlObHJOQWlXRXlHdEw4QTRhbzNwRE13Q3RyYjJ5cjwvWDUwOUNlcnRpZmljYXRlPjwvWDUwOURhdGE%2BPC9LZXlJbmZvPjwvU2lnbmF0dXJlPjxzYW1sMjpTdWJqZWN0PjxzYW1sMjpOYW1lSUQgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6bmFtZWlkLWZvcm1hdDp0cmFuc2llbnQiIE5hbWVRdWFsaWZpZXI9Imh0dHBzOi8vcG9zdGVpZC5wb3N0ZS5pdCI%2BU1BJRC02NDBmOWNmNC04ZjE2LTRkN2YtODhmNi05MThhZGI1ZjBlMDE8L3NhbWwyOk5hbWVJRD48c2FtbDI6U3ViamVjdENvbmZpcm1hdGlvbiBNZXRob2Q9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpjbTpiZWFyZXIiPjxzYW1sMjpTdWJqZWN0Q29uZmlybWF0aW9uRGF0YSBJblJlc3BvbnNlVG89Il9kYmFmODVjM2UzNDQ1YzQzZmI4NTA3YTlmMjk4MzE1OSIgTm90T25PckFmdGVyPSIyMDE2LTA2LTE2VDA4OjQ0OjMwLjk4OFoiIFJlY2lwaWVudD0iaHR0cDovL3d3dy51bmlyb21hMS5pdC9zcGlkL2NvbnN1bWUiLz48L3NhbWwyOlN1YmplY3RDb25maXJtYXRpb24%2BPC9zYW1sMjpTdWJqZWN0PjxzYW1sMjpDb25kaXRpb25zIE5vdEJlZm9yZT0iMjAxNi0wNi0xNlQwODo0MzozMC45ODhaIiBOb3RPbk9yQWZ0ZXI9IjIwMTYtMDYtMTZUMDg6NDQ6MzAuOTg4WiI%2BPHNhbWwyOkF1ZGllbmNlUmVzdHJpY3Rpb24%2BPHNhbWwyOkF1ZGllbmNlPmh0dHA6Ly93d3cudW5pcm9tYTEuaXQ8L3NhbWwyOkF1ZGllbmNlPjwvc2FtbDI6QXVkaWVuY2VSZXN0cmljdGlvbj48L3NhbWwyOkNvbmRpdGlvbnM%2BPHNhbWwyOkF1dGhuU3RhdGVtZW50IEF1dGhuSW5zdGFudD0iMjAxNi0wNi0xNlQwODo0MzozMC45ODhaIiBTZXNzaW9uSW5kZXg9ImNGZERObTA3QXUvU2hEZlVzOURmNVAzTkllOXUwZWhIVHQrZEhHMlZuT2VrVUd5SUxQYjRZdz09Ij48c2FtbDI6QXV0aG5Db250ZXh0PjxzYW1sMjpBdXRobkNvbnRleHRDbGFzc1JlZj51cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YWM6Y2xhc3NlczpTcGlkTDE8L3NhbWwyOkF1dGhuQ29udGV4dENsYXNzUmVmPjwvc2FtbDI6QXV0aG5Db250ZXh0Pjwvc2FtbDI6QXV0aG5TdGF0ZW1lbnQ%2BPHNhbWwyOkF0dHJpYnV0ZVN0YXRlbWVudD48c2FtbDI6QXR0cmlidXRlIE5hbWU9ImZpc2NhbE51bWJlciI%2BPHNhbWwyOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI%2BVElOSVQtR0hOTFJUODVBMjFMMjE5UDwvc2FtbDI6QXR0cmlidXRlVmFsdWU%2BPC9zYW1sMjpBdHRyaWJ1dGU%2BPC9zYW1sMjpBdHRyaWJ1dGVTdGF0ZW1lbnQ%2BPC9zYW1sMjpBc3NlcnRpb24%2BPC9zYW1sMnA6UmVzcG9uc2U%2B&RelayState=uniroma1_srelay1');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (28, 'cf3a1eb6-61e4-49cb-bdc7-728dc23d1ca6', 'GET', 'http://192.168.56.103:8888/api/prvd/uniroma1/authnreq/login?idp=pt&attrindex=0&binding=post&srelay=uniroma1_srelay1', '2017-07-17 00:36:12.60967+02', '192.168.56.1', NULL);
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (29, '82028b38-50f4-4788-997b-d380e417ce4a', 'GET', 'http://192.168.56.103:8888/api/jwt/getByType?type=jwt1', '2017-07-17 00:46:03.912877+02', '192.168.56.1', NULL);
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (30, 'da250cca-5ff2-4f6e-b530-42cc4f03f429', 'POST', 'http://192.168.56.103:8888/api/prvd/uniroma1/consume', '2017-07-17 17:48:40.383877+02', '192.168.56.1', 'SAMLResponse=PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8%2BPHNhbWwycDpSZXNwb25zZSB4bWxuczpzYW1sMnA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCIgRGVzdGluYXRpb249Imh0dHA6Ly93d3cudW5pcm9tYTEuaXQvc3BpZC9jb25zdW1lIiBJRD0iX2QzYmI5ODg0LTY2NTctNDhkMS05YWE1LTdiOWQ1ODNiZWE3NyIgSW5SZXNwb25zZVRvPSJfZGJhZjg1YzNlMzQ0NWM0M2ZiODUwN2E5ZjI5ODMxNTkiIElzc3VlSW5zdGFudD0iMjAxNi0wNi0xNlQwODo0MzozMS45ODhaIiBWZXJzaW9uPSIyLjAiPjxzYW1sMjpJc3N1ZXIgeG1sbnM6c2FtbDI9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPmh0dHBzOi8vcG9zdGVpZC5wb3N0ZS5pdDwvc2FtbDI6SXNzdWVyPjxTaWduYXR1cmUgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxTaWduZWRJbmZvPjxDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8%2BPFNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNyc2Etc2hhMSIvPjxSZWZlcmVuY2UgVVJJPSIjX2QzYmI5ODg0LTY2NTctNDhkMS05YWE1LTdiOWQ1ODNiZWE3NyI%2BPFRyYW5zZm9ybXM%2BPFRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8%2BPFRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvVHJhbnNmb3Jtcz48RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3NoYTEiLz48RGlnZXN0VmFsdWU%2BQmdDTFgxZkZOUE51YmU2dE5Fa3V6TzBZdXRJPTwvRGlnZXN0VmFsdWU%2BPC9SZWZlcmVuY2U%2BPC9TaWduZWRJbmZvPjxTaWduYXR1cmVWYWx1ZT5GemRlRzg2dTgvQ1VZY1Mvc2l4OGJydzh3aXhYUHJzRFRLTnJmUmkvM2lSRmlJWmVPZHJMS1lLWHBhSEFmVEhFVVQ0eGw5U1haNVFhDQpiYlRxWkc2M2VhOEtuT0dyYXI2Vm9reWRYVWFUcXpaVk9XK05PWHVWdi80bzJ5TlhoZ2tDdFk2YklNdW5GQUx5ak9IN3RYZVJlZ0srDQpiRWZ4aDRZUGZ0c0Z2RGg4aWg3UTNjaXFyOFJRV2R2VkZCU2hCd0R1R0ZIdE5uaEhzSDhFdWljY0s0V25WTXpLcksvMXFnNWxldDBHDQo0Ym03cklhQk93dTFGRUtDNENYV2U0K00vR2dIR0RMbWpoVnVqeTVZK2hNUENJUitYb2E2OUdHTnNoOTJhUFFlYzVOVlNxVklzT1JjDQpDMkdaZEpuMFV3b2xudDZGaGNGSnNTTjNLem5HYWhQcDRsY0VHQT09PC9TaWduYXR1cmVWYWx1ZT48S2V5SW5mbz48WDUwOURhdGE%2BPFg1MDlDZXJ0aWZpY2F0ZT5NSUlFS3pDQ0F4T2dBd0lCQWdJREUyWTBNQTBHQ1NxR1NJYjNEUUVCQ3dVQU1HQXhDekFKQmdOVkJBWVRBa2xVTVJnd0ZnWURWUVFLDQpEQTlRYjNOMFpXTnZiU0JUTG5BdVFTNHhJREFlQmdOVkJBc01GME5sY25ScFptbGpZWFJwYjI0Z1FYVjBhRzl5YVhSNU1SVXdFd1lEDQpWUVFEREF4UWIzTjBaV052YlNCRFFUTXdIaGNOTVRZd01qSTJNVFUxTWpRMFdoY05NakV3TWpJMk1UVTFNalEwV2pCeE1Rc3dDUVlEDQpWUVFHRXdKSlZERU9NQXdHQTFVRUNBd0ZTWFJoYkhreERUQUxCZ05WQkFjTUJGSnZiV1V4SGpBY0JnTlZCQW9NRlZCdmMzUmxJRWwwDQpZV3hwWVc1bElGTXVjQzVCTGpFTk1Bc0dBMVVFQ3d3RVUxQkpSREVVTUJJR0ExVUVBd3dMU1VSUUxWQnZjM1JsU1VRd2dnRWlNQTBHDQpDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRRFpGRXRKb0VIRkFqcENhWmNqNURWV3JSRHlhTFp5dTMxWEFwc2xibzg3DQpDeVd6NjFPSk10dzZRUVUwTWRDdHJZYnRTSjZ2Snd4Ny82RVVqc1ozdTR4M0VQTGRsa3lpR09xdWtQd0FUdjRjN1RWT1VWczVvbklxDQpUcGhNOWIrQUhSZzRlaGlNR2VzbS85ZDdSSWFMdU43OWlQVXZkTG42V1AzaWRBZkV3K3JoSi93WUVRMGgxWG01b3NOVWd0V2NCR2F2DQpaSWpMc3NXTnJERGZKWXhYSDNRWjBrSTZmZUV2TENKd2dqWExHa0J1aEZlaE5oTTRmaGJYOWlVQ1d3d2tKM0pzUDIrK1JjL2lUQTBMDQpaaGlVc1hOTnE3Z0JjTEFKOVVYMlYxZFdqVHpCSGV2ZkhzcHp0NGUwVmdJSXdiRFJxc1J0RjhWVVBTRFlZYkxvcXdiTHQxOFhBZ01CDQpBQUdqZ2R3d2dka3dSZ1lEVlIwZ0JEOHdQVEF3QmdjclRBc0JBZ0VCTUNVd0l3WUlLd1lCQlFVSEFnRVdGMmgwZEhBNkx5OTNkM2N1DQpjRzl6ZEdWalpYSjBMbWwwTUFrR0J5dE1Dd0VCQ2dJd0RnWURWUjBQQVFIL0JBUURBZ1N3TUI4R0ExVWRJd1FZTUJhQUZLYzBYUDJGDQpCeVlVMmwwZ0Z6R0tFOHpWU3pmbU1EOEdBMVVkSHdRNE1EWXdOS0F5b0RDR0xtaDBkSEE2THk5d2IzTjBaV05sY25RdWNHOXpkR1V1DQphWFF2Y0c5emRHVmpiMjFqWVRNdlkzSnNNeTVqY213d0hRWURWUjBPQkJZRUZFdnJpa1pRa2ZCanVpVHB4RXhTQmU4d0dnc3lNQTBHDQpDU3FHU0liM0RRRUJDd1VBQTRJQkFRQk5BdzhVb2VpQ0YrMXJGczI3ZDNiRWVmNkNMZS9QSmdhOUVmd0tJdGpNREQ5UXpUL0ZTaFJXDQpLTEhsSzY5TUhMMVpMUFJQdnVXVVRrSU9IVHBOcUJQSUx2TzF1MTNiU2crNm8rMk9kcUFrQ0JrYlRxYkdqV1NQTGFUVVZOVjZNYlhtDQp2dHREOFZkOXZJWmcxeEJCRzNGYWkxM2R3dlNqM2hBWmQ4dWc4YThmVzF5L2lEYlJDNUQxTytIbEhEdXZJVzRMYkowOTNqZGorb1p3DQpTeWQyMTZndFhMMDBRQTBDMXVNdUR2OVdmOUl4bmlUYjcxMGRSU2dJY000L2VSNzgzMmZaZ2RPc29hbEZ6R1lXeFNDczhXT1pyanB1DQpiMWZkYVJTRXVDUWsyK2dtZHNpUmNUczlFcVBDQ05pTmxyTkFpV0V5R3RMOEE0YW8zcERNd0N0cmIyeXI8L1g1MDlDZXJ0aWZpY2F0ZT48L1g1MDlEYXRhPjwvS2V5SW5mbz48L1NpZ25hdHVyZT48c2FtbDJwOlN0YXR1cz48c2FtbDJwOlN0YXR1c0NvZGUgVmFsdWU9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6U3VjY2VzcyIvPjwvc2FtbDJwOlN0YXR1cz48c2FtbDI6QXNzZXJ0aW9uIHhtbG5zOnNhbWwyPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0iXzQ2ZTllOTJlLTk2ODItNDBkYy05OTIxLTg4YmE2ZjIzMDhlMyIgSXNzdWVJbnN0YW50PSIyMDE2LTA2LTE2VDA4OjQzOjMwLjk4OVoiIFZlcnNpb249IjIuMCI%2BPHNhbWwyOklzc3VlciBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OmVudGl0eSI%2BaHR0cHM6Ly9wb3N0ZWlkLnBvc3RlLml0PC9zYW1sMjpJc3N1ZXI%2BPFNpZ25hdHVyZSB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI%2BPFNpZ25lZEluZm8%2BPENhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3JzYS1zaGExIi8%2BPFJlZmVyZW5jZSBVUkk9IiNfNDZlOWU5MmUtOTY4Mi00MGRjLTk5MjEtODhiYTZmMjMwOGUzIj48VHJhbnNmb3Jtcz48VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz48VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8%2BPC9UcmFuc2Zvcm1zPjxEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjc2hhMSIvPjxEaWdlc3RWYWx1ZT5xYUlsWGZFaWtlWmw1cXY1ZkZ1YkV3ZVN2OWM9PC9EaWdlc3RWYWx1ZT48L1JlZmVyZW5jZT48L1NpZ25lZEluZm8%2BPFNpZ25hdHVyZVZhbHVlPlNoOXBRMnFFaXd1dThNMGQwd3VwNXAyY3l5ZmkvYWE2VG93UjNTK0RyTTRpTWpIUW1oZVNkeTUweDhOd044SlVDenBqSktlUmt1L1MNCk1NRjF2YjlBcWt5clh4UlJhYTU1VlRNd2xOa0FYbmtEanFIQ3FvanRaci9DQjMxbHU5bEhWcjNQV1M1NC8xL1ZKRTBsdUNUbEl5akENCnV4SzZTQktaWW9mS2hWRThiLzBYTE93Yk1pUVRtZG00eG1yVGk5YVYzT09zeTRpNTNaOUJkUnVnWmxpYldJKys5ZGE5ZzFhMjJoVVgNCmRzdSt6ZGZLcUN3elQ0Q1FUejBZYjBrbGI2cnhqc0VDUC9wekljM0pXSWJGbXU4djcxdk9Na1VTTHlOODV6MzJodVRlQi9JcG9aMTcNCjg0SjlocVh5SFZQeEd1b09VMkgxK1BxNnoyZU1GbGVsMFB3TjlnPT08L1NpZ25hdHVyZVZhbHVlPjxLZXlJbmZvPjxYNTA5RGF0YT48WDUwOUNlcnRpZmljYXRlPk1JSUVLekNDQXhPZ0F3SUJBZ0lERTJZME1BMEdDU3FHU0liM0RRRUJDd1VBTUdBeEN6QUpCZ05WQkFZVEFrbFVNUmd3RmdZRFZRUUsNCkRBOVFiM04wWldOdmJTQlRMbkF1UVM0eElEQWVCZ05WQkFzTUYwTmxjblJwWm1sallYUnBiMjRnUVhWMGFHOXlhWFI1TVJVd0V3WUQNClZRUUREQXhRYjNOMFpXTnZiU0JEUVRNd0hoY05NVFl3TWpJMk1UVTFNalEwV2hjTk1qRXdNakkyTVRVMU1qUTBXakJ4TVFzd0NRWUQNClZRUUdFd0pKVkRFT01Bd0dBMVVFQ0F3RlNYUmhiSGt4RFRBTEJnTlZCQWNNQkZKdmJXVXhIakFjQmdOVkJBb01GVkJ2YzNSbElFbDANCllXeHBZVzVsSUZNdWNDNUJMakVOTUFzR0ExVUVDd3dFVTFCSlJERVVNQklHQTFVRUF3d0xTVVJRTFZCdmMzUmxTVVF3Z2dFaU1BMEcNCkNTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFEWkZFdEpvRUhGQWpwQ2FaY2o1RFZXclJEeWFMWnl1MzFYQXBzbGJvODcNCkN5V3o2MU9KTXR3NlFRVTBNZEN0cllidFNKNnZKd3g3LzZFVWpzWjN1NHgzRVBMZGxreWlHT3F1a1B3QVR2NGM3VFZPVVZzNW9uSXENClRwaE05YitBSFJnNGVoaU1HZXNtLzlkN1JJYUx1Tjc5aVBVdmRMbjZXUDNpZEFmRXcrcmhKL3dZRVEwaDFYbTVvc05VZ3RXY0JHYXYNClpJakxzc1dOckREZkpZeFhIM1FaMGtJNmZlRXZMQ0p3Z2pYTEdrQnVoRmVoTmhNNGZoYlg5aVVDV3d3a0ozSnNQMisrUmMvaVRBMEwNClpoaVVzWE5OcTdnQmNMQUo5VVgyVjFkV2pUekJIZXZmSHNwenQ0ZTBWZ0lJd2JEUnFzUnRGOFZVUFNEWVliTG9xd2JMdDE4WEFnTUINCkFBR2pnZHd3Z2Rrd1JnWURWUjBnQkQ4d1BUQXdCZ2NyVEFzQkFnRUJNQ1V3SXdZSUt3WUJCUVVIQWdFV0YyaDBkSEE2THk5M2QzY3UNCmNHOXpkR1ZqWlhKMExtbDBNQWtHQnl0TUN3RUJDZ0l3RGdZRFZSMFBBUUgvQkFRREFnU3dNQjhHQTFVZEl3UVlNQmFBRktjMFhQMkYNCkJ5WVUybDBnRnpHS0U4elZTemZtTUQ4R0ExVWRId1E0TURZd05LQXlvRENHTG1oMGRIQTZMeTl3YjNOMFpXTmxjblF1Y0c5emRHVXUNCmFYUXZjRzl6ZEdWamIyMWpZVE12WTNKc015NWpjbXd3SFFZRFZSME9CQllFRkV2cmlrWlFrZkJqdWlUcHhFeFNCZTh3R2dzeU1BMEcNCkNTcUdTSWIzRFFFQkN3VUFBNElCQVFCTkF3OFVvZWlDRisxckZzMjdkM2JFZWY2Q0xlL1BKZ2E5RWZ3S0l0ak1ERDlRelQvRlNoUlcNCktMSGxLNjlNSEwxWkxQUlB2dVdVVGtJT0hUcE5xQlBJTHZPMXUxM2JTZys2bysyT2RxQWtDQmtiVHFiR2pXU1BMYVRVVk5WNk1iWG0NCnZ0dEQ4VmQ5dklaZzF4QkJHM0ZhaTEzZHd2U2ozaEFaZDh1ZzhhOGZXMXkvaURiUkM1RDFPK0hsSER1dklXNExiSjA5M2pkaitvWncNClN5ZDIxNmd0WEwwMFFBMEMxdU11RHY5V2Y5SXhuaVRiNzEwZFJTZ0ljTTQvZVI3ODMyZlpnZE9zb2FsRnpHWVd4U0NzOFdPWnJqcHUNCmIxZmRhUlNFdUNRazIrZ21kc2lSY1RzOUVxUENDTmlObHJOQWlXRXlHdEw4QTRhbzNwRE13Q3RyYjJ5cjwvWDUwOUNlcnRpZmljYXRlPjwvWDUwOURhdGE%2BPC9LZXlJbmZvPjwvU2lnbmF0dXJlPjxzYW1sMjpTdWJqZWN0PjxzYW1sMjpOYW1lSUQgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6bmFtZWlkLWZvcm1hdDp0cmFuc2llbnQiIE5hbWVRdWFsaWZpZXI9Imh0dHBzOi8vcG9zdGVpZC5wb3N0ZS5pdCI%2BU1BJRC02NDBmOWNmNC04ZjE2LTRkN2YtODhmNi05MThhZGI1ZjBlMDE8L3NhbWwyOk5hbWVJRD48c2FtbDI6U3ViamVjdENvbmZpcm1hdGlvbiBNZXRob2Q9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpjbTpiZWFyZXIiPjxzYW1sMjpTdWJqZWN0Q29uZmlybWF0aW9uRGF0YSBJblJlc3BvbnNlVG89Il9kYmFmODVjM2UzNDQ1YzQzZmI4NTA3YTlmMjk4MzE1OSIgTm90T25PckFmdGVyPSIyMDE2LTA2LTE2VDA4OjQ0OjMwLjk4OFoiIFJlY2lwaWVudD0iaHR0cDovL3d3dy51bmlyb21hMS5pdC9zcGlkL2NvbnN1bWUiLz48L3NhbWwyOlN1YmplY3RDb25maXJtYXRpb24%2BPC9zYW1sMjpTdWJqZWN0PjxzYW1sMjpDb25kaXRpb25zIE5vdEJlZm9yZT0iMjAxNi0wNi0xNlQwODo0MzozMC45ODhaIiBOb3RPbk9yQWZ0ZXI9IjIwMTYtMDYtMTZUMDg6NDQ6MzAuOTg4WiI%2BPHNhbWwyOkF1ZGllbmNlUmVzdHJpY3Rpb24%2BPHNhbWwyOkF1ZGllbmNlPmh0dHA6Ly93d3cudW5pcm9tYTEuaXQ8L3NhbWwyOkF1ZGllbmNlPjwvc2FtbDI6QXVkaWVuY2VSZXN0cmljdGlvbj48L3NhbWwyOkNvbmRpdGlvbnM%2BPHNhbWwyOkF1dGhuU3RhdGVtZW50IEF1dGhuSW5zdGFudD0iMjAxNi0wNi0xNlQwODo0MzozMC45ODhaIiBTZXNzaW9uSW5kZXg9ImNGZERObTA3QXUvU2hEZlVzOURmNVAzTkllOXUwZWhIVHQrZEhHMlZuT2VrVUd5SUxQYjRZdz09Ij48c2FtbDI6QXV0aG5Db250ZXh0PjxzYW1sMjpBdXRobkNvbnRleHRDbGFzc1JlZj51cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YWM6Y2xhc3NlczpTcGlkTDE8L3NhbWwyOkF1dGhuQ29udGV4dENsYXNzUmVmPjwvc2FtbDI6QXV0aG5Db250ZXh0Pjwvc2FtbDI6QXV0aG5TdGF0ZW1lbnQ%2BPHNhbWwyOkF0dHJpYnV0ZVN0YXRlbWVudD48c2FtbDI6QXR0cmlidXRlIE5hbWU9ImZpc2NhbE51bWJlciI%2BPHNhbWwyOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI%2BVElOSVQtR0hOTFJUODVBMjFMMjE5UDwvc2FtbDI6QXR0cmlidXRlVmFsdWU%2BPC9zYW1sMjpBdHRyaWJ1dGU%2BPC9zYW1sMjpBdHRyaWJ1dGVTdGF0ZW1lbnQ%2BPC9zYW1sMjpBc3NlcnRpb24%2BPC9zYW1sMnA6UmVzcG9uc2U%2B&RelayState=uniroma1_srelay1');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (31, 'f8a2aa5b-328a-4e03-9a70-c5035a443833', 'GET', 'http://192.168.56.103:8888/api/prvd/pt/metadata', '2017-07-24 07:11:39.953544+02', '192.168.56.1', NULL);
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (32, '5db2d1df-afd0-4826-aa4f-e78c839e31ad', 'GET', 'http://192.168.56.103:8888/api/prvd/aruba/metadata', '2017-07-24 07:13:18.33862+02', '192.168.56.1', NULL);
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (33, '7300b010-0d10-4bc9-a603-297a794a4851', 'POST', 'http://192.168.56.103:8888/api/prvd/sapienza/metadata/verify', '2017-07-24 07:21:13.667019+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "metadata": "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<md:EntityDescriptor ID=\"_76b0b4bb-956e-4c40-b493-281cbed5b7f3\" entityID=\"https://loginspid.aruba.it\" xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\"><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><ds:Reference URI=\"#_76b0b4bb-956e-4c40-b493-281cbed5b7f3\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>ZrvubwZHMwi2OESXVBWa1RMz9M0S4WK9CylEPhPeZXs=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>iGhOzmnfTGowXk99BH9MekN742hx38dUorFQFkGyZuvhqjLWaSdxz5zYULDH59FdBY1FvjZFoLZmSTBVU+uT6hzyXAMRcaLp0eGoGXjOIG2viU0YBnnIlaHdzY8H0hs2IepAcH0z0/d78bPBASZJezzjONUjpfsUSYRLQ46Tg6PANWTVkSZprGsaDLOvEPYcgjQsiLahVucloGKXrlfttwrl23xGQZQ1umgF+zIi7291JcOcXVYbDMzeWXhsbmzZo9EGUWVaqbsnvNje3nMwF4x7C9z6NnrbpPIulgG2ZAAnvxRw593okL7w2mTsmisqFN5HUTgs9SVFBrHTp1ygxA==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIExTCCA62gAwIBAgIQIHtEvEhGM77HwqsuvSbi9zANBgkqhkiG9w0BAQsFADBsMQswCQYDVQQG\nEwJJVDEYMBYGA1UECgwPQXJ1YmFQRUMgUy5wLkEuMSEwHwYDVQQLDBhDZXJ0aWZpY2F0aW9uIEF1\ndGhvcml0eUIxIDAeBgNVBAMMF0FydWJhUEVDIFMucC5BLiBORyBDQSAyMB4XDTE3MDEyMzAwMDAw\nMFoXDTIwMDEyMzIzNTk1OVowgaAxCzAJBgNVBAYTAklUMRYwFAYDVQQKDA1BcnViYSBQRUMgc3Bh\nMREwDwYDVQQLDAhQcm9kb3R0bzEWMBQGA1UEAwwNcGVjLml0IHBlYy5pdDEZMBcGA1UEBRMQWFhY\nWFhYMDBYMDBYMDAwWDEPMA0GA1UEKgwGcGVjLml0MQ8wDQYDVQQEDAZwZWMuaXQxETAPBgNVBC4T\nCDE2MzQ1MzgzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqt2oHJhcp03l73p+QYpE\nJ+f3jYYj0W0gos0RItZx/w4vpsiKBygaqDNVWSwfo1aPdVDIX13f62O+lBki29KTt+QWv5K6SGHD\nUXYPntRdEQlicIBh2Z0HfrM7fDl+xeJrMp1s4dsSQAuB5TJOlFZq7xCQuukytGWBTvjfcN/os5aE\nsEg+RbtZHJR26SbbUcIqWb27Swgj/9jwK+tvzLnP4w8FNvEOrNfR0XwTMNDFrwbOCuWgthv5jNBs\nVZaoqNwiA/MxYt+gTOMj/o5PWKk8Wpm6o/7/+lWAoxh0v8x9OkbIi+YaFpIxuCcUqsrJJk63x2gH\nCc2nr+yclYUhsKD/AwIDAQABo4IBLDCCASgwDgYDVR0PAQH/BAQDAgeAMB0GA1UdDgQWBBTKQ3+N\nPGcXFk8nX994vMTVpba1EzBHBgNVHSAEQDA+MDwGCysGAQQBgegtAQEBMC0wKwYIKwYBBQUHAgEW\nH2h0dHBzOi8vY2EuYXJ1YmFwZWMuaXQvY3BzLmh0bWwwWAYDVR0fBFEwTzBNoEugSYZHaHR0cDov\nL2NybC5hcnViYXBlYy5pdC9BcnViYVBFQ1NwQUNlcnRpZmljYXRpb25BdXRob3JpdHlCL0xhdGVz\ndENSTC5jcmwwHwYDVR0jBBgwFoAU8v9jQBwRQv3M3/FZ9m7omYcxR3kwMwYIKwYBBQUHAQEEJzAl\nMCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5hcnViYXBlYy5pdDANBgkqhkiG9w0BAQsFAAOCAQEA\nnEw0NuaspbpDjA5wggwFtfQydU6b3Bw2/KXPRKS2JoqGmx0SYKj+L17A2KUBa2c7gDtKXYz0FLT6\n0Bv0pmBN/oYCgVMEBJKqwRwdki9YjEBwyCZwNEx1kDAyyqFEVU9vw/OQfrAdp7MTbuZGFKknVt7b\n9wOYy/Op9FiUaTg6SuOy0ep+rqhihltYNAAl4L6fY45mHvqa5vvVG30OvLW/S4uvRYUXYwY6KhWv\nNdDf5CnFugnuEZtHJrVe4wx9aO5GvFLFZ/mQ35C5mXPQ7nIb0CDdLBJdz82nUoLSA5BUbeXAUkfa\nhW/hLxLdhks68/TK694xVIuiB40pvMmJwxIyDA==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIIExTCCA62gAwIBAgIQIHtEvEhGM77HwqsuvSbi9zANBgkqhkiG9w0BAQsFADBsMQswCQYDVQQG\nEwJJVDEYMBYGA1UECgwPQXJ1YmFQRUMgUy5wLkEuMSEwHwYDVQQLDBhDZXJ0aWZpY2F0aW9uIEF1\ndGhvcml0eUIxIDAeBgNVBAMMF0FydWJhUEVDIFMucC5BLiBORyBDQSAyMB4XDTE3MDEyMzAwMDAw\nMFoXDTIwMDEyMzIzNTk1OVowgaAxCzAJBgNVBAYTAklUMRYwFAYDVQQKDA1BcnViYSBQRUMgc3Bh\nMREwDwYDVQQLDAhQcm9kb3R0bzEWMBQGA1UEAwwNcGVjLml0IHBlYy5pdDEZMBcGA1UEBRMQWFhY\nWFhYMDBYMDBYMDAwWDEPMA0GA1UEKgwGcGVjLml0MQ8wDQYDVQQEDAZwZWMuaXQxETAPBgNVBC4T\nCDE2MzQ1MzgzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqt2oHJhcp03l73p+QYpE\nJ+f3jYYj0W0gos0RItZx/w4vpsiKBygaqDNVWSwfo1aPdVDIX13f62O+lBki29KTt+QWv5K6SGHD\nUXYPntRdEQlicIBh2Z0HfrM7fDl+xeJrMp1s4dsSQAuB5TJOlFZq7xCQuukytGWBTvjfcN/os5aE\nsEg+RbtZHJR26SbbUcIqWb27Swgj/9jwK+tvzLnP4w8FNvEOrNfR0XwTMNDFrwbOCuWgthv5jNBs\nVZaoqNwiA/MxYt+gTOMj/o5PWKk8Wpm6o/7/+lWAoxh0v8x9OkbIi+YaFpIxuCcUqsrJJk63x2gH\nCc2nr+yclYUhsKD/AwIDAQABo4IBLDCCASgwDgYDVR0PAQH/BAQDAgeAMB0GA1UdDgQWBBTKQ3+N\nPGcXFk8nX994vMTVpba1EzBHBgNVHSAEQDA+MDwGCysGAQQBgegtAQEBMC0wKwYIKwYBBQUHAgEW\nH2h0dHBzOi8vY2EuYXJ1YmFwZWMuaXQvY3BzLmh0bWwwWAYDVR0fBFEwTzBNoEugSYZHaHR0cDov\nL2NybC5hcnViYXBlYy5pdC9BcnViYVBFQ1NwQUNlcnRpZmljYXRpb25BdXRob3JpdHlCL0xhdGVz\ndENSTC5jcmwwHwYDVR0jBBgwFoAU8v9jQBwRQv3M3/FZ9m7omYcxR3kwMwYIKwYBBQUHAQEEJzAl\nMCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5hcnViYXBlYy5pdDANBgkqhkiG9w0BAQsFAAOCAQEA\nnEw0NuaspbpDjA5wggwFtfQydU6b3Bw2/KXPRKS2JoqGmx0SYKj+L17A2KUBa2c7gDtKXYz0FLT6\n0Bv0pmBN/oYCgVMEBJKqwRwdki9YjEBwyCZwNEx1kDAyyqFEVU9vw/OQfrAdp7MTbuZGFKknVt7b\n9wOYy/Op9FiUaTg6SuOy0ep+rqhihltYNAAl4L6fY45mHvqa5vvVG30OvLW/S4uvRYUXYwY6KhWv\nNdDf5CnFugnuEZtHJrVe4wx9aO5GvFLFZ/mQ35C5mXPQ7nIb0CDdLBJdz82nUoLSA5BUbeXAUkfa\nhW/hLxLdhks68/TK694xVIuiB40pvMmJwxIyDA==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://loginspid.aruba.it/ServiceLogoutRequest\"/><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://loginspid.aruba.it/ServiceLogoutRequest\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://loginspid.aruba.it/ServiceLoginWelcome\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://loginspid.aruba.it/ServiceLoginWelcome\"/><saml2:Attribute FriendlyName=\"Codice identificativo SPID\" Name=\"spidCode\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/><saml2:Attribute FriendlyName=\"Nome\" Name=\"name\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/><saml2:Attribute FriendlyName=\"Cognome\" Name=\"familyName\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/><saml2:Attribute FriendlyName=\"Luogo di nascita\" Name=\"placeOfBirth\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/><saml2:Attribute FriendlyName=\"Provincia di nascita\" Name=\"countyOfBirth\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/><saml2:Attribute FriendlyName=\"Data di nascita\" Name=\"dateOfBirth\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/><saml2:Attribute FriendlyName=\"Sesso\" Name=\"gender\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/><saml2:Attribute FriendlyName=\"Ragione o denominazione sociale\" Name=\"companyName\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/><saml2:Attribute FriendlyName=\"Sede legale\" Name=\"registeredOffice\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/><saml2:Attribute FriendlyName=\"Codice fiscale\" Name=\"fiscalNumber\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/><saml2:Attribute FriendlyName=\"Partita IVA\" Name=\"ivaCode\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/><saml2:Attribute FriendlyName=\"Documento d''identitÃ \" Name=\"idCard\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/><saml2:Attribute FriendlyName=\"Numero di telefono mobile\" Name=\"mobilePhone\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/><saml2:Attribute FriendlyName=\"Indirizzo di posta elettronica\" Name=\"email\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/><saml2:Attribute FriendlyName=\"Domicilio fisico\" Name=\"address\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/><saml2:Attribute FriendlyName=\"Data di scadenza identitÃ \" Name=\"expirationDate\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/><saml2:Attribute FriendlyName=\"Domicilio digitale\" Name=\"digitalAddress\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang=\"it\">ArubaPEC S.p.A.</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"it\">ArubaPEC S.p.A.</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"it\">https://www.pec.it/</md:OrganizationURL></md:Organization></md:EntityDescriptor>"
  },
  "apiVersion": "0.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (34, '468b79ed-b570-46f7-ba02-85e3b6df7263', 'POST', 'http://192.168.56.103:8888/api/prvd/infocert/metadata/verify', '2017-07-24 07:24:08.973486+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "metadata": "<?xml version=\"1.0\" standalone=\"no\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"_25b183c4c721960977003fb04ec600b4\" cacheDuration=\"P0Y0M30DT0H0M0.000S\" entityID=\"https://identity.infocert.it\"><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"#_25b183c4c721960977003fb04ec600b4\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>hKbiiLWanDYNT69FQLh4uWlI6rVdAfoNXltq8WE83No=</DigestValue></Reference></SignedInfo><SignatureValue>nqWCyBqw40iHn3OEF9qVnJIzX9xmTzoq3EE9pbpPtrrAnjBWKTI2GxCAH84oD7BArJ/oBWOEQ0iJzFLwdtJK56ly8MwFAiYdCuNm9wHd03gSGBMxaWbhQSfwkwRCmMbzxcXJGMhh4JECOdZ87KR861A+S2EPyWBHC9yx8iRZ4UtmrGpf3UWyFJsCEjCLZv+a/ld6WnkP43OqJhs84BQWrH+Z1QOy1GDDYe+sItvQ1BhOomDT6x+ZsrMntgAItF+1kQxJ5CPRzGkYb10vr0WYukAAfcQ46fJ7Jje5ZBG8heBd61wxwKfuDDt6MD191PLWHjgy6sgA6zwXikGkQsTeeA==</SignatureValue><KeyInfo><X509Data><X509Certificate>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</X509Certificate></X509Data></KeyInfo></Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlsso\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlsso\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio fisico\" Name=\"address\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Ragione o denominazione sociale\" Name=\"companyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Provincia di nascita\" Name=\"countyOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di nascita\" Name=\"dateOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio digitale\" Name=\"digitalAddress\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Indirizzo di posta elettronica\" Name=\"email\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di scadenza identita\" Name=\"expirationDate\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Cognome\" Name=\"familyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice fiscale\" Name=\"fiscalNumber\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sesso\" Name=\"gender\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Documento d''identita\" Name=\"idCard\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Partita IVA\" Name=\"ivaCode\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Numero di telefono mobile\" Name=\"mobilePhone\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Nome\" Name=\"name\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Luogo di nascita\" Name=\"placeOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sede legale\" Name=\"registeredOffice\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice identificativo SPID\" Name=\"spidCode\"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"it\">https://www.infocert.it</md:OrganizationURL><md:OrganizationURL xml:lang=\"en\">https://www.infocert.it/international/?lang=en</md:OrganizationURL><md:OrganizationURL xml:lang=\"fr\">https://www.infocert.it/international/?lang=fr</md:OrganizationURL><md:OrganizationURL xml:lang=\"de\">https://www.infocert.it/international/?lang=de</md:OrganizationURL></md:Organization></md:EntityDescriptor>"
  },
  "apiVersion": "0.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (35, '757800a1-3a57-403c-a457-2ee289411550', 'POST', 'http://192.168.56.103:8888/api/prvd/infocrt/metadata/verify', '2017-07-24 07:24:30.8323+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "metadata": "<?xml version=\"1.0\" standalone=\"no\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"_25b183c4c721960977003fb04ec600b4\" cacheDuration=\"P0Y0M30DT0H0M0.000S\" entityID=\"https://identity.infocert.it\"><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"#_25b183c4c721960977003fb04ec600b4\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>hKbiiLWanDYNT69FQLh4uWlI6rVdAfoNXltq8WE83No=</DigestValue></Reference></SignedInfo><SignatureValue>nqWCyBqw40iHn3OEF9qVnJIzX9xmTzoq3EE9pbpPtrrAnjBWKTI2GxCAH84oD7BArJ/oBWOEQ0iJzFLwdtJK56ly8MwFAiYdCuNm9wHd03gSGBMxaWbhQSfwkwRCmMbzxcXJGMhh4JECOdZ87KR861A+S2EPyWBHC9yx8iRZ4UtmrGpf3UWyFJsCEjCLZv+a/ld6WnkP43OqJhs84BQWrH+Z1QOy1GDDYe+sItvQ1BhOomDT6x+ZsrMntgAItF+1kQxJ5CPRzGkYb10vr0WYukAAfcQ46fJ7Jje5ZBG8heBd61wxwKfuDDt6MD191PLWHjgy6sgA6zwXikGkQsTeeA==</SignatureValue><KeyInfo><X509Data><X509Certificate>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</X509Certificate></X509Data></KeyInfo></Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlsso\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlsso\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio fisico\" Name=\"address\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Ragione o denominazione sociale\" Name=\"companyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Provincia di nascita\" Name=\"countyOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di nascita\" Name=\"dateOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio digitale\" Name=\"digitalAddress\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Indirizzo di posta elettronica\" Name=\"email\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di scadenza identita\" Name=\"expirationDate\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Cognome\" Name=\"familyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice fiscale\" Name=\"fiscalNumber\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sesso\" Name=\"gender\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Documento d''identita\" Name=\"idCard\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Partita IVA\" Name=\"ivaCode\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Numero di telefono mobile\" Name=\"mobilePhone\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Nome\" Name=\"name\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Luogo di nascita\" Name=\"placeOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sede legale\" Name=\"registeredOffice\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice identificativo SPID\" Name=\"spidCode\"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"it\">https://www.infocert.it</md:OrganizationURL><md:OrganizationURL xml:lang=\"en\">https://www.infocert.it/international/?lang=en</md:OrganizationURL><md:OrganizationURL xml:lang=\"fr\">https://www.infocert.it/international/?lang=fr</md:OrganizationURL><md:OrganizationURL xml:lang=\"de\">https://www.infocert.it/international/?lang=de</md:OrganizationURL></md:Organization></md:EntityDescriptor>"
  },
  "apiVersion": "0.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (36, '28563084-da70-4611-b273-ac053782172e', 'GET', 'http://192.168.56.103:8888/api/prvd/infocrt/metadata', '2017-07-24 07:25:47.394613+02', '192.168.56.1', NULL);
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (37, 'a2a6b775-2fcf-4ff9-86c5-2d167374c4bb', 'POST', 'http://192.168.56.103:8888/api/prvd/infocrt/metadata/verify', '2017-07-24 07:29:21.245587+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "metadata": "<?xml version=\"1.0\" standalone=\"no\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"_25b183c4c721960977003fb04ec600b4\" cacheDuration=\"P0Y0M30DT0H0M0.000S\" entityID=\"https://identity.infocert.it\"><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"#_25b183c4c721960977003fb04ec600b4\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>hKbiiLWanDYNT69FQLh4uWlI6rVdAfoNXltq8WE83No=</DigestValue></Reference></SignedInfo><SignatureValue>nqWCyBqw40iHn3OEF9qVnJIzX9xmTzoq3EE9pbpPtrrAnjBWKTI2GxCAH84oD7BArJ/oBWOEQ0iJzFLwdtJK56ly8MwFAiYdCuNm9wHd03gSGBMxaWbhQSfwkwRCmMbzxcXJGMhh4JECOdZ87KR861A+S2EPyWBHC9yx8iRZ4UtmrGpf3UWyFJsCEjCLZv+a/ld6WnkP43OqJhs84BQWrH+Z1QOy1GDDYe+sItvQ1BhOomDT6x+ZsrMntgAItF+1kQxJ5CPRzGkYb10vr0WYukAAfcQ46fJ7Jje5ZBG8heBd61wxwKfuDDt6MD191PLWHjgy6sgA6zwXikGkQsTeeA==</SignatureValue><KeyInfo><X509Data><X509Certificate>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</X509Certificate></X509Data></KeyInfo></Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlsso\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlsso\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio fisico\" Name=\"address\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Ragione o denominazione sociale\" Name=\"companyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Provincia di nascita\" Name=\"countyOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di nascita\" Name=\"dateOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio digitale\" Name=\"digitalAddress\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Indirizzo di posta elettronica\" Name=\"email\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di scadenza identita\" Name=\"expirationDate\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Cognome\" Name=\"familyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice fiscale\" Name=\"fiscalNumber\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sesso\" Name=\"gender\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Documento d''identita\" Name=\"idCard\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Partita IVA\" Name=\"ivaCode\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Numero di telefono mobile\" Name=\"mobilePhone\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Nome\" Name=\"name\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Luogo di nascita\" Name=\"placeOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sede legale\" Name=\"registeredOffice\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice identificativo SPID\" Name=\"spidCode\"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"it\">https://www.infocert.it</md:OrganizationURL><md:OrganizationURL xml:lang=\"en\">https://www.infocert.it/international/?lang=en</md:OrganizationURL><md:OrganizationURL xml:lang=\"fr\">https://www.infocert.it/international/?lang=fr</md:OrganizationURL><md:OrganizationURL xml:lang=\"de\">https://www.infocert.it/international/?lang=de</md:OrganizationURL></md:Organization></md:EntityDescriptor>"
  },
  "apiVersion": "0.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (38, '0b3aa39e-909f-4dd0-9902-2e6bdfb3490c', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 12:48:28.329726+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\" standalone=\"no\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"_25b183c4c721960977003fb04ec600b4\" cacheDuration=\"P0Y0M30DT0H0M0.000S\" entityID=\"https://identity.infocert.it\"><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"#_25b183c4c721960977003fb04ec600b4\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>hKbiiLWanDYNT69FQLh4uWlI6rVdAfoNXltq8WE83No=</DigestValue></Reference></SignedInfo><SignatureValue>nqWCyBqw40iHn3OEF9qVnJIzX9xmTzoq3EE9pbpPtrrAnjBWKTI2GxCAH84oD7BArJ/oBWOEQ0iJzFLwdtJK56ly8MwFAiYdCuNm9wHd03gSGBMxaWbhQSfwkwRCmMbzxcXJGMhh4JECOdZ87KR861A+S2EPyWBHC9yx8iRZ4UtmrGpf3UWyFJsCEjCLZv+a/ld6WnkP43OqJhs84BQWrH+Z1QOy1GDDYe+sItvQ1BhOomDT6x+ZsrMntgAItF+1kQxJ5CPRzGkYb10vr0WYukAAfcQ46fJ7Jje5ZBG8heBd61wxwKfuDDt6MD191PLWHjgy6sgA6zwXikGkQsTeeA==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIGbDCCBVSgAwIBAgIDA+76MA0GCSqGSIb3DQEBCwUAMIGGMQswCQYDVQQGEwJJVDEVMBMGA1UECgwMSU5GT0NFUlQgU1BBMRswGQYDVQQLDBJFbnRlIENlcnRpZmljYXRvcmUxFDASBgNVBAUTCzA3OTQ1MjExMDA2MS0wKwYDVQQDDCRJbmZvQ2VydCBTZXJ2aXppIGRpIENlcnRpZmljYXppb25lIDIwHhcNMTYwMTEyMDkyNDI4WhcNMTkwMTEyMDAwMDAwWjCBsTEUMBIGA1UELhMLMDc5NDUyMTEwMDYxDzANBgkqhkiG9w0BCQEWADEUMBIGA1UEBRMLMDc5NDUyMTEwMDYxHTAbBgNVBAMMFGlkZW50aXR5LmluZm9jZXJ0Lml0MRQwEgYDVQQLDAtJbmZvQ2VydCBJRDEhMB8GA1UECgwYSW5mb0NlcnQgU3BBLzA3OTQ1MjExMDA2MQ0wCwYDVQQHDARSb21hMQswCQYDVQQGEwJJVDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALDysrpnXB+it94LSuAmOgyFDilZ8nuSEVOFl1PX/HtgK3W25B/tqJBsyZwrAIXxg5XHYd3+i7bFoBjuduzfqhvSv9WYCVtggsz5a3sbOpU54DaOLgoCmd4nIsINwKzCmT1UNXBGjS+Xt5F3lV+v2Ayr4rAsPnkE2084BLmwcIX3w7+rx/Nd+/5HfaAMaORICYinUIvbZ5e/plUj87s1YEpep/DcC0uMFE66jFrcnHVOeHCrDh+tAZAiGew4BVJjLr0hfS4ZeaE43TJlHb00GZNfpfzGcOPbzWlSB5iF/cZbTRHmPsn0gALfpPNViniFBVqSaoywZwvkFosrehRUCNkCAwEAAaOCArQwggKwMBMGA1UdJQQMMAoGCCsGAQUFBwMCMCUGA1UdEgQeMByBGmZpcm1hLmRpZ2l0YWxlQGluZm9jZXJ0Lml0MGUGA1UdIAReMFwwWgYGK0wkAQEIMFAwTgYIKwYBBQUHAgIwQgxASW5mb0NlcnQgU3BBIFNTTCwgU01JTUUgYW5kIGRpZ2l0YWwgc2lnbmF0dXJlIENsaWVudCBDZXJ0aWZpY2F0ZTA3BggrBgEFBQcBAQQrMCkwJwYIKwYBBQUHMAGGG2h0dHA6Ly9vY3NwLnNjLmluZm9jZXJ0Lml0LzCB7AYDVR0fBIHkMIHhMDSgMqAwhi5odHRwOi8vY3JsLmluZm9jZXJ0Lml0L2NybHMvc2Vydml6aTIvQ1JMMDEuY3JsMIGooIGloIGihoGfbGRhcDovL2xkYXAuaW5mb2NlcnQuaXQvY24lM0RJbmZvQ2VydCUyMFNlcnZpemklMjBkaSUyMENlcnRpZmljYXppb25lJTIwMiUyMENSTDAxLG91JTNERW50ZSUyMENlcnRpZmljYXRvcmUsbyUzRElORk9DRVJUJTIwU1BBLEMlM0RJVD9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0MA4GA1UdDwEB/wQEAwIEsDCBswYDVR0jBIGrMIGogBTpNppkKVKhWv5ppMSDt4B9D2oSeKGBjKSBiTCBhjELMAkGA1UEBhMCSVQxFTATBgNVBAoMDElORk9DRVJUIFNQQTEbMBkGA1UECwwSRW50ZSBDZXJ0aWZpY2F0b3JlMRQwEgYDVQQFEwswNzk0NTIxMTAwNjEtMCsGA1UEAwwkSW5mb0NlcnQgU2Vydml6aSBkaSBDZXJ0aWZpY2F6aW9uZSAyggECMB0GA1UdDgQWBBTi8mIRU4ue/0lKSfv4gSQhoZQvozANBgkqhkiG9w0BAQsFAAOCAQEAUCXyjmfzxmyVQbK4cf79zj5qMZVAAjDMTR1UGFcS2IibICh3S3Uf22lPGQfm+MX9tiweETW7fBLW6lrR2ofXBz/FfU98A/AA9GZDrbGhBxoc+RoqkHVYRqEuXOq6z3X9DuvsdsfKeO3p4eXbXlCcxD2PP5fFqcZxx1WZ1HRamiGk9fMN1iT3aPa3q7TfRD6W6+XgafjXieZ8bCa1FGIfapbqsWa91jdn4xiJpbmTTq1/Zjs5RCZYzmMEV9rSuSVgFtONb8+xKC4ohMVxAUw2yZHwd4dDyBLkapuaWkzhW939+gjeoKz04Ds2C52d/kln7ehdu9LkzvRI6UAEpAYLgg==</X509Certificate></X509Data></KeyInfo></Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIIGbDCCBVSgAwIBAgIDA+76MA0GCSqGSIb3DQEBCwUAMIGGMQswCQYDVQQGEwJJVDEVMBMGA1UECgwMSU5GT0NFUlQgU1BBMRswGQYDVQQLDBJFbnRlIENlcnRpZmljYXRvcmUxFDASBgNVBAUTCzA3OTQ1MjExMDA2MS0wKwYDVQQDDCRJbmZvQ2VydCBTZXJ2aXppIGRpIENlcnRpZmljYXppb25lIDIwHhcNMTYwMTEyMDkyNDI4WhcNMTkwMTEyMDAwMDAwWjCBsTEUMBIGA1UELhMLMDc5NDUyMTEwMDYxDzANBgkqhkiG9w0BCQEWADEUMBIGA1UEBRMLMDc5NDUyMTEwMDYxHTAbBgNVBAMMFGlkZW50aXR5LmluZm9jZXJ0Lml0MRQwEgYDVQQLDAtJbmZvQ2VydCBJRDEhMB8GA1UECgwYSW5mb0NlcnQgU3BBLzA3OTQ1MjExMDA2MQ0wCwYDVQQHDARSb21hMQswCQYDVQQGEwJJVDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALDysrpnXB+it94LSuAmOgyFDilZ8nuSEVOFl1PX/HtgK3W25B/tqJBsyZwrAIXxg5XHYd3+i7bFoBjuduzfqhvSv9WYCVtggsz5a3sbOpU54DaOLgoCmd4nIsINwKzCmT1UNXBGjS+Xt5F3lV+v2Ayr4rAsPnkE2084BLmwcIX3w7+rx/Nd+/5HfaAMaORICYinUIvbZ5e/plUj87s1YEpep/DcC0uMFE66jFrcnHVOeHCrDh+tAZAiGew4BVJjLr0hfS4ZeaE43TJlHb00GZNfpfzGcOPbzWlSB5iF/cZbTRHmPsn0gALfpPNViniFBVqSaoywZwvkFosrehRUCNkCAwEAAaOCArQwggKwMBMGA1UdJQQMMAoGCCsGAQUFBwMCMCUGA1UdEgQeMByBGmZpcm1hLmRpZ2l0YWxlQGluZm9jZXJ0Lml0MGUGA1UdIAReMFwwWgYGK0wkAQEIMFAwTgYIKwYBBQUHAgIwQgxASW5mb0NlcnQgU3BBIFNTTCwgU01JTUUgYW5kIGRpZ2l0YWwgc2lnbmF0dXJlIENsaWVudCBDZXJ0aWZpY2F0ZTA3BggrBgEFBQcBAQQrMCkwJwYIKwYBBQUHMAGGG2h0dHA6Ly9vY3NwLnNjLmluZm9jZXJ0Lml0LzCB7AYDVR0fBIHkMIHhMDSgMqAwhi5odHRwOi8vY3JsLmluZm9jZXJ0Lml0L2NybHMvc2Vydml6aTIvQ1JMMDEuY3JsMIGooIGloIGihoGfbGRhcDovL2xkYXAuaW5mb2NlcnQuaXQvY24lM0RJbmZvQ2VydCUyMFNlcnZpemklMjBkaSUyMENlcnRpZmljYXppb25lJTIwMiUyMENSTDAxLG91JTNERW50ZSUyMENlcnRpZmljYXRvcmUsbyUzRElORk9DRVJUJTIwU1BBLEMlM0RJVD9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0MA4GA1UdDwEB/wQEAwIEsDCBswYDVR0jBIGrMIGogBTpNppkKVKhWv5ppMSDt4B9D2oSeKGBjKSBiTCBhjELMAkGA1UEBhMCSVQxFTATBgNVBAoMDElORk9DRVJUIFNQQTEbMBkGA1UECwwSRW50ZSBDZXJ0aWZpY2F0b3JlMRQwEgYDVQQFEwswNzk0NTIxMTAwNjEtMCsGA1UEAwwkSW5mb0NlcnQgU2Vydml6aSBkaSBDZXJ0aWZpY2F6aW9uZSAyggECMB0GA1UdDgQWBBTi8mIRU4ue/0lKSfv4gSQhoZQvozANBgkqhkiG9w0BAQsFAAOCAQEAUCXyjmfzxmyVQbK4cf79zj5qMZVAAjDMTR1UGFcS2IibICh3S3Uf22lPGQfm+MX9tiweETW7fBLW6lrR2ofXBz/FfU98A/AA9GZDrbGhBxoc+RoqkHVYRqEuXOq6z3X9DuvsdsfKeO3p4eXbXlCcxD2PP5fFqcZxx1WZ1HRamiGk9fMN1iT3aPa3q7TfRD6W6+XgafjXieZ8bCa1FGIfapbqsWa91jdn4xiJpbmTTq1/Zjs5RCZYzmMEV9rSuSVgFtONb8+xKC4ohMVxAUw2yZHwd4dDyBLkapuaWkzhW939+gjeoKz04Ds2C52d/kln7ehdu9LkzvRI6UAEpAYLgg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlsso\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlsso\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio fisico\" Name=\"address\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Ragione o denominazione sociale\" Name=\"companyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Provincia di nascita\" Name=\"countyOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di nascita\" Name=\"dateOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio digitale\" Name=\"digitalAddress\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Indirizzo di posta elettronica\" Name=\"email\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di scadenza identita\" Name=\"expirationDate\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Cognome\" Name=\"familyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice fiscale\" Name=\"fiscalNumber\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sesso\" Name=\"gender\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Documento d''identita\" Name=\"idCard\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Partita IVA\" Name=\"ivaCode\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Numero di telefono mobile\" Name=\"mobilePhone\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Nome\" Name=\"name\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Luogo di nascita\" Name=\"placeOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sede legale\" Name=\"registeredOffice\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice identificativo SPID\" Name=\"spidCode\"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"it\">https://www.infocert.it</md:OrganizationURL><md:OrganizationURL xml:lang=\"en\">https://www.infocert.it/international/?lang=en</md:OrganizationURL><md:OrganizationURL xml:lang=\"fr\">https://www.infocert.it/international/?lang=fr</md:OrganizationURL><md:OrganizationURL xml:lang=\"de\">https://www.infocert.it/international/?lang=de</md:OrganizationURL></md:Organization></md:EntityDescriptor>"
  },
  "apiVersion": "0.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (39, 'a137eed5-c3bf-4991-b1e1-18e81813986a', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 12:53:15.538479+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\" standalone=\"no\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"_25b183c4c721960977003fb04ec600b4\" cacheDuration=\"P0Y0M30DT0H0M0.000S\" entityID=\"https://identity.infocert.it\"><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"#_25b183c4c721960977003fb04ec600b4\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>hKbiiLWanDYNT69FQLh4uWlI6rVdAfoNXltq8WE83No=</DigestValue></Reference></SignedInfo><SignatureValue>nqWCyBqw40iHn3OEF9qVnJIzX9xmTzoq3EE9pbpPtrrAnjBWKTI2GxCAH84oD7BArJ/oBWOEQ0iJzFLwdtJK56ly8MwFAiYdCuNm9wHd03gSGBMxaWbhQSfwkwRCmMbzxcXJGMhh4JECOdZ87KR861A+S2EPyWBHC9yx8iRZ4UtmrGpf3UWyFJsCEjCLZv+a/ld6WnkP43OqJhs84BQWrH+Z1QOy1GDDYe+sItvQ1BhOomDT6x+ZsrMntgAItF+1kQxJ5CPRzGkYb10vr0WYukAAfcQ46fJ7Jje5ZBG8heBd61wxwKfuDDt6MD191PLWHjgy6sgA6zwXikGkQsTeeA==</SignatureValue><KeyInfo><X509Data><X509Certificate>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</X509Certificate></X509Data></KeyInfo></Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlsso\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlsso\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio fisico\" Name=\"address\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Ragione o denominazione sociale\" Name=\"companyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Provincia di nascita\" Name=\"countyOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di nascita\" Name=\"dateOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio digitale\" Name=\"digitalAddress\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Indirizzo di posta elettronica\" Name=\"email\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di scadenza identita\" Name=\"expirationDate\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Cognome\" Name=\"familyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice fiscale\" Name=\"fiscalNumber\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sesso\" Name=\"gender\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Documento d''identita\" Name=\"idCard\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Partita IVA\" Name=\"ivaCode\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Numero di telefono mobile\" Name=\"mobilePhone\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Nome\" Name=\"name\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Luogo di nascita\" Name=\"placeOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sede legale\" Name=\"registeredOffice\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice identificativo SPID\" Name=\"spidCode\"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"it\">https://www.infocert.it</md:OrganizationURL><md:OrganizationURL xml:lang=\"en\">https://www.infocert.it/international/?lang=en</md:OrganizationURL><md:OrganizationURL xml:lang=\"fr\">https://www.infocert.it/international/?lang=fr</md:OrganizationURL><md:OrganizationURL xml:lang=\"de\">https://www.infocert.it/international/?lang=de</md:OrganizationURL></md:Organization></md:EntityDescriptor>"
  },
  "apiVersion": "0.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (40, 'e90aa46a-85a2-4acf-be9e-a4c2770e00ec', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 13:00:44.058989+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\" standalone=\"no\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"_25b183c4c721960977003fb04ec600b4\" cacheDuration=\"P0Y0M30DT0H0M0.000S\" entityID=\"https://identity.infocert.it\"><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"#_25b183c4c721960977003fb04ec600b4\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>hKbiiLWanDYNT69FQLh4uWlI6rVdAfoNXltq8WE83No=</DigestValue></Reference></SignedInfo><SignatureValue>nqWCyBqw40iHn3OEF9qVnJIzX9xmTzoq3EE9pbpPtrrAnjBWKTI2GxCAH84oD7BArJ/oBWOEQ0iJzFLwdtJK56ly8MwFAiYdCuNm9wHd03gSGBMxaWbhQSfwkwRCmMbzxcXJGMhh4JECOdZ87KR861A+S2EPyWBHC9yx8iRZ4UtmrGpf3UWyFJsCEjCLZv+a/ld6WnkP43OqJhs84BQWrH+Z1QOy1GDDYe+sItvQ1BhOomDT6x+ZsrMntgAItF+1kQxJ5CPRzGkYb10vr0WYukAAfcQ46fJ7Jje5ZBG8heBd61wxwKfuDDt6MD191PLWHjgy6sgA6zwXikGkQsTeeA==</SignatureValue><KeyInfo><X509Data><X509Certificate>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</X509Certificate></X509Data></KeyInfo></Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlsso\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlsso\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio fisico\" Name=\"address\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Ragione o denominazione sociale\" Name=\"companyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Provincia di nascita\" Name=\"countyOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di nascita\" Name=\"dateOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio digitale\" Name=\"digitalAddress\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Indirizzo di posta elettronica\" Name=\"email\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di scadenza identita\" Name=\"expirationDate\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Cognome\" Name=\"familyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice fiscale\" Name=\"fiscalNumber\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sesso\" Name=\"gender\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Documento d''identita\" Name=\"idCard\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Partita IVA\" Name=\"ivaCode\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Numero di telefono mobile\" Name=\"mobilePhone\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Nome\" Name=\"name\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Luogo di nascita\" Name=\"placeOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sede legale\" Name=\"registeredOffice\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice identificativo SPID\" Name=\"spidCode\"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"it\">https://www.infocert.it</md:OrganizationURL><md:OrganizationURL xml:lang=\"en\">https://www.infocert.it/international/?lang=en</md:OrganizationURL><md:OrganizationURL xml:lang=\"fr\">https://www.infocert.it/international/?lang=fr</md:OrganizationURL><md:OrganizationURL xml:lang=\"de\">https://www.infocert.it/international/?lang=de</md:OrganizationURL></md:Organization></md:EntityDescriptor>"
  },
  "apiVersion": "0.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (41, '0f2924c4-f779-48ce-9451-75fc4eba466e', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 13:03:51.023491+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\" standalone=\"no\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"_25b183c4c721960977003fb04ec600b4\" cacheDuration=\"P0Y0M30DT0H0M0.000S\" entityID=\"https://identity.infocert.it\"><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"#_25b183c4c721960977003fb04ec600b4\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>hKbiiLWanDYNT69FQLh4uWlI6rVdAfoNXltq8WE83No=</DigestValue></Reference></SignedInfo><SignatureValue>nqWCyBqw40iHn3OEF9qVnJIzX9xmTzoq3EE9pbpPtrrAnjBWKTI2GxCAH84oD7BArJ/oBWOEQ0iJzFLwdtJK56ly8MwFAiYdCuNm9wHd03gSGBMxaWbhQSfwkwRCmMbzxcXJGMhh4JECOdZ87KR861A+S2EPyWBHC9yx8iRZ4UtmrGpf3UWyFJsCEjCLZv+a/ld6WnkP43OqJhs84BQWrH+Z1QOy1GDDYe+sItvQ1BhOomDT6x+ZsrMntgAItF+1kQxJ5CPRzGkYb10vr0WYukAAfcQ46fJ7Jje5ZBG8heBd61wxwKfuDDt6MD191PLWHjgy6sgA6zwXikGkQsTeeA==</SignatureValue><KeyInfo><X509Data><X509Certificate>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</X509Certificate></X509Data></KeyInfo></Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlsso\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlsso\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio fisico\" Name=\"address\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Ragione o denominazione sociale\" Name=\"companyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Provincia di nascita\" Name=\"countyOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di nascita\" Name=\"dateOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio digitale\" Name=\"digitalAddress\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Indirizzo di posta elettronica\" Name=\"email\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di scadenza identita\" Name=\"expirationDate\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Cognome\" Name=\"familyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice fiscale\" Name=\"fiscalNumber\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sesso\" Name=\"gender\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Documento d''identita\" Name=\"idCard\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Partita IVA\" Name=\"ivaCode\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Numero di telefono mobile\" Name=\"mobilePhone\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Nome\" Name=\"name\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Luogo di nascita\" Name=\"placeOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sede legale\" Name=\"registeredOffice\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice identificativo SPID\" Name=\"spidCode\"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"it\">https://www.infocert.it</md:OrganizationURL><md:OrganizationURL xml:lang=\"en\">https://www.infocert.it/international/?lang=en</md:OrganizationURL><md:OrganizationURL xml:lang=\"fr\">https://www.infocert.it/international/?lang=fr</md:OrganizationURL><md:OrganizationURL xml:lang=\"de\">https://www.infocert.it/international/?lang=de</md:OrganizationURL></md:Organization></md:EntityDescriptor>"
  },
  "apiVersion": "0.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (42, 'cbcf8f27-ce63-4132-a8d7-bb23b4391d88', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 15:54:04.332084+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\" standalone=\"no\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"_25b183c4c721960977003fb04ec600b4\" cacheDuration=\"P0Y0M30DT0H0M0.000S\" entityID=\"https://identity.infocert.it\"><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"#_25b183c4c721960977003fb04ec600b4\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>hKbiiLWanDYNT69FQLh4uWlI6rVdAfoNXltq8WE83No=</DigestValue></Reference></SignedInfo><SignatureValue>nqWCyBqw40iHn3OEF9qVnJIzX9xmTzoq3EE9pbpPtrrAnjBWKTI2GxCAH84oD7BArJ/oBWOEQ0iJzFLwdtJK56ly8MwFAiYdCuNm9wHd03gSGBMxaWbhQSfwkwRCmMbzxcXJGMhh4JECOdZ87KR861A+S2EPyWBHC9yx8iRZ4UtmrGpf3UWyFJsCEjCLZv+a/ld6WnkP43OqJhs84BQWrH+Z1QOy1GDDYe+sItvQ1BhOomDT6x+ZsrMntgAItF+1kQxJ5CPRzGkYb10vr0WYukAAfcQ46fJ7Jje5ZBG8heBd61wxwKfuDDt6MD191PLWHjgy6sgA6zwXikGkQsTeeA==</SignatureValue><KeyInfo><X509Data><X509Certificate>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</X509Certificate></X509Data></KeyInfo></Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlsso\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlsso\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio fisico\" Name=\"address\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Ragione o denominazione sociale\" Name=\"companyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Provincia di nascita\" Name=\"countyOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di nascita\" Name=\"dateOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio digitale\" Name=\"digitalAddress\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Indirizzo di posta elettronica\" Name=\"email\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di scadenza identita\" Name=\"expirationDate\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Cognome\" Name=\"familyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice fiscale\" Name=\"fiscalNumber\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sesso\" Name=\"gender\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Documento d''identita\" Name=\"idCard\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Partita IVA\" Name=\"ivaCode\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Numero di telefono mobile\" Name=\"mobilePhone\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Nome\" Name=\"name\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Luogo di nascita\" Name=\"placeOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sede legale\" Name=\"registeredOffice\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice identificativo SPID\" Name=\"spidCode\"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"it\">https://www.infocert.it</md:OrganizationURL><md:OrganizationURL xml:lang=\"en\">https://www.infocert.it/international/?lang=en</md:OrganizationURL><md:OrganizationURL xml:lang=\"fr\">https://www.infocert.it/international/?lang=fr</md:OrganizationURL><md:OrganizationURL xml:lang=\"de\">https://www.infocert.it/international/?lang=de</md:OrganizationURL></md:Organization></md:EntityDescriptor>"
  },
  "apiVersion": "0.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (43, '2ba9d5db-1cda-49ee-b718-273185f6d820', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 16:01:56.46802+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\" standalone=\"no\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"_25b183c4c721960977003fb04ec600b4\" cacheDuration=\"P0Y0M30DT0H0M0.000S\" entityID=\"https://identity.infocert.it\"><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"#_25b183c4c721960977003fb04ec600b4\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>hKbiiLWanDYNT69FQLh4uWlI6rVdAfoNXltq8WE83No=</DigestValue></Reference></SignedInfo><SignatureValue>nqWCyBqw40iHn3OEF9qVnJIzX9xmTzoq3EE9pbpPtrrAnjBWKTI2GxCAH84oD7BArJ/oBWOEQ0iJzFLwdtJK56ly8MwFAiYdCuNm9wHd03gSGBMxaWbhQSfwkwRCmMbzxcXJGMhh4JECOdZ87KR861A+S2EPyWBHC9yx8iRZ4UtmrGpf3UWyFJsCEjCLZv+a/ld6WnkP43OqJhs84BQWrH+Z1QOy1GDDYe+sItvQ1BhOomDT6x+ZsrMntgAItF+1kQxJ5CPRzGkYb10vr0WYukAAfcQ46fJ7Jje5ZBG8heBd61wxwKfuDDt6MD191PLWHjgy6sgA6zwXikGkQsTeeA==</SignatureValue><KeyInfo><X509Data><X509Certificate>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</X509Certificate></X509Data></KeyInfo></Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlsso\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlsso\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio fisico\" Name=\"address\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Ragione o denominazione sociale\" Name=\"companyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Provincia di nascita\" Name=\"countyOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di nascita\" Name=\"dateOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio digitale\" Name=\"digitalAddress\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Indirizzo di posta elettronica\" Name=\"email\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di scadenza identita\" Name=\"expirationDate\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Cognome\" Name=\"familyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice fiscale\" Name=\"fiscalNumber\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sesso\" Name=\"gender\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Documento d''identita\" Name=\"idCard\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Partita IVA\" Name=\"ivaCode\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Numero di telefono mobile\" Name=\"mobilePhone\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Nome\" Name=\"name\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Luogo di nascita\" Name=\"placeOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sede legale\" Name=\"registeredOffice\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice identificativo SPID\" Name=\"spidCode\"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"it\">https://www.infocert.it</md:OrganizationURL><md:OrganizationURL xml:lang=\"en\">https://www.infocert.it/international/?lang=en</md:OrganizationURL><md:OrganizationURL xml:lang=\"fr\">https://www.infocert.it/international/?lang=fr</md:OrganizationURL><md:OrganizationURL xml:lang=\"de\">https://www.infocert.it/international/?lang=de</md:OrganizationURL></md:Organization></md:EntityDescriptor>"
  },
  "apiVersion": "0.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (44, '6db9838e-433c-4787-b9b6-613d68bf7f5b', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 16:41:10.306097+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\" standalone=\"no\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"_25b183c4c721960977003fb04ec600b4\" cacheDuration=\"P0Y0M30DT0H0M0.000S\" entityID=\"https://identity.infocert.it\"><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"#_25b183c4c721960977003fb04ec600b4\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>hKbiiLWanDYNT69FQLh4uWlI6rVdAfoNXltq8WE83No=</DigestValue></Reference></SignedInfo><SignatureValue>nqWCyBqw40iHn3OEF9qVnJIzX9xmTzoq3EE9pbpPtrrAnjBWKTI2GxCAH84oD7BArJ/oBWOEQ0iJzFLwdtJK56ly8MwFAiYdCuNm9wHd03gSGBMxaWbhQSfwkwRCmMbzxcXJGMhh4JECOdZ87KR861A+S2EPyWBHC9yx8iRZ4UtmrGpf3UWyFJsCEjCLZv+a/ld6WnkP43OqJhs84BQWrH+Z1QOy1GDDYe+sItvQ1BhOomDT6x+ZsrMntgAItF+1kQxJ5CPRzGkYb10vr0WYukAAfcQ46fJ7Jje5ZBG8heBd61wxwKfuDDt6MD191PLWHjgy6sgA6zwXikGkQsTeeA==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIGbDCCBVSgAwIBAgIDA+76MA0GCSqGSIb3DQEBCwUAMIGGMQswCQYDVQQGEwJJVDEVMBMGA1UECgwMSU5GT0NFUlQgU1BBMRswGQYDVQQLDBJFbnRlIENlcnRpZmljYXRvcmUxFDASBgNVBAUTCzA3OTQ1MjExMDA2MS0wKwYDVQQDDCRJbmZvQ2VydCBTZXJ2aXppIGRpIENlcnRpZmljYXppb25lIDIwHhcNMTYwMTEyMDkyNDI4WhcNMTkwMTEyMDAwMDAwWjCBsTEUMBIGA1UELhMLMDc5NDUyMTEwMDYxDzANBgkqhkiG9w0BCQEWADEUMBIGA1UEBRMLMDc5NDUyMTEwMDYxHTAbBgNVBAMMFGlkZW50aXR5LmluZm9jZXJ0Lml0MRQwEgYDVQQLDAtJbmZvQ2VydCBJRDEhMB8GA1UECgwYSW5mb0NlcnQgU3BBLzA3OTQ1MjExMDA2MQ0wCwYDVQQHDARSb21hMQswCQYDVQQGEwJJVDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALDysrpnXB+it94LSuAmOgyFDilZ8nuSEVOFl1PX/HtgK3W25B/tqJBsyZwrAIXxg5XHYd3+i7bFoBjuduzfqhvSv9WYCVtggsz5a3sbOpU54DaOLgoCmd4nIsINwKzCmT1UNXBGjS+Xt5F3lV+v2Ayr4rAsPnkE2084BLmwcIX3w7+rx/Nd+/5HfaAMaORICYinUIvbZ5e/plUj87s1YEpep/DcC0uMFE66jFrcnHVOeHCrDh+tAZAiGew4BVJjLr0hfS4ZeaE43TJlHb00GZNfpfzGcOPbzWlSB5iF/cZbTRHmPsn0gALfpPNViniFBVqSaoywZwvkFosrehRUCNkCAwEAAaOCArQwggKwMBMGA1UdJQQMMAoGCCsGAQUFBwMCMCUGA1UdEgQeMByBGmZpcm1hLmRpZ2l0YWxlQGluZm9jZXJ0Lml0MGUGA1UdIAReMFwwWgYGK0wkAQEIMFAwTgYIKwYBBQUHAgIwQgxASW5mb0NlcnQgU3BBIFNTTCwgU01JTUUgYW5kIGRpZ2l0YWwgc2lnbmF0dXJlIENsaWVudCBDZXJ0aWZpY2F0ZTA3BggrBgEFBQcBAQQrMCkwJwYIKwYBBQUHMAGGG2h0dHA6Ly9vY3NwLnNjLmluZm9jZXJ0Lml0LzCB7AYDVR0fBIHkMIHhMDSgMqAwhi5odHRwOi8vY3JsLmluZm9jZXJ0Lml0L2NybHMvc2Vydml6aTIvQ1JMMDEuY3JsMIGooIGloIGihoGfbGRhcDovL2xkYXAuaW5mb2NlcnQuaXQvY24lM0RJbmZvQ2VydCUyMFNlcnZpemklMjBkaSUyMENlcnRpZmljYXppb25lJTIwMiUyMENSTDAxLG91JTNERW50ZSUyMENlcnRpZmljYXRvcmUsbyUzRElORk9DRVJUJTIwU1BBLEMlM0RJVD9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0MA4GA1UdDwEB/wQEAwIEsDCBswYDVR0jBIGrMIGogBTpNppkKVKhWv5ppMSDt4B9D2oSeKGBjKSBiTCBhjELMAkGA1UEBhMCSVQxFTATBgNVBAoMDElORk9DRVJUIFNQQTEbMBkGA1UECwwSRW50ZSBDZXJ0aWZpY2F0b3JlMRQwEgYDVQQFEwswNzk0NTIxMTAwNjEtMCsGA1UEAwwkSW5mb0NlcnQgU2Vydml6aSBkaSBDZXJ0aWZpY2F6aW9uZSAyggECMB0GA1UdDgQWBBTi8mIRU4ue/0lKSfv4gSQhoZQvozANBgkqhkiG9w0BAQsFAAOCAQEAUCXyjmfzxmyVQbK4cf79zj5qMZVAAjDMTR1UGFcS2IibICh3S3Uf22lPGQfm+MX9tiweETW7fBLW6lrR2ofXBz/FfU98A/AA9GZDrbGhBxoc+RoqkHVYRqEuXOq6z3X9DuvsdsfKeO3p4eXbXlCcxD2PP5fFqcZxx1WZ1HRamiGk9fMN1iT3aPa3q7TfRD6W6+XgafjXieZ8bCa1FGIfapbqsWa91jdn4xiJpbmTTq1/Zjs5RCZYzmMEV9rSuSVgFtONb8+xKC4ohMVxAUw2yZHwd4dDyBLkapuaWkzhW939+gjeoKz04Ds2C52d/kln7ehdu9LkzvRI6UAEpAYLgg==</X509Certificate></X509Data></KeyInfo></Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlsso\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlsso\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio fisico\" Name=\"address\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Ragione o denominazione sociale\" Name=\"companyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Provincia di nascita\" Name=\"countyOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di nascita\" Name=\"dateOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio digitale\" Name=\"digitalAddress\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Indirizzo di posta elettronica\" Name=\"email\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di scadenza identita\" Name=\"expirationDate\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Cognome\" Name=\"familyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice fiscale\" Name=\"fiscalNumber\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sesso\" Name=\"gender\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Documento d''identita\" Name=\"idCard\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Partita IVA\" Name=\"ivaCode\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Numero di telefono mobile\" Name=\"mobilePhone\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Nome\" Name=\"name\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Luogo di nascita\" Name=\"placeOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sede legale\" Name=\"registeredOffice\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice identificativo SPID\" Name=\"spidCode\"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"it\">https://www.infocert.it</md:OrganizationURL><md:OrganizationURL xml:lang=\"en\">https://www.infocert.it/international/?lang=en</md:OrganizationURL><md:OrganizationURL xml:lang=\"fr\">https://www.infocert.it/international/?lang=fr</md:OrganizationURL><md:OrganizationURL xml:lang=\"de\">https://www.infocert.it/international/?lang=de</md:OrganizationURL></md:Organization></md:EntityDescriptor>"
  },
  "apiVersion": "0.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (45, '2587a044-ac07-4207-a47a-1cf11e754020', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 16:41:57.805928+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\" standalone=\"no\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"_25b183c4c721960977003fb04ec600b4\" cacheDuration=\"P0Y0M30DT0H0M0.000S\" entityID=\"https://identity.infocert.it\"><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"#_25b183c4c721960977003fb04ec600b4\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>hKbiiLWanDYNT69FQLh4uWlI6rVdAfoNXltq8WE83No=</DigestValue></Reference></SignedInfo><SignatureValue>nqWCyBqw40iHn3OEF9qVnJIzX9xmTzoq3EE9pbpPtrrAnjBWKTI2GxCAH84oD7BArJ/oBWOEQ0iJzFLwdtJK56ly8MwFAiYdCuNm9wHd03gSGBMxaWbhQSfwkwRCmMbzxcXJGMhh4JECOdZ87KR861A+S2EPyWBHC9yx8iRZ4UtmrGpf3UWyFJsCEjCLZv+a/ld6WnkP43OqJhs84BQWrH+Z1QOy1GDDYe+sItvQ1BhOomDT6x+ZsrMntgAItF+1kQxJ5CPRzGkYb10vr0WYukAAfcQ46fJ7Jje5ZBG8heBd61wxwKfuDDt6MD191PLWHjgy6sgA6zwXikGkQsTeeA==</SignatureValue><KeyInfo><X509Data><X509Certificate>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</X509Certificate></X509Data></KeyInfo></Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlsso\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlsso\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio fisico\" Name=\"address\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Ragione o denominazione sociale\" Name=\"companyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Provincia di nascita\" Name=\"countyOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di nascita\" Name=\"dateOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio digitale\" Name=\"digitalAddress\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Indirizzo di posta elettronica\" Name=\"email\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di scadenza identita\" Name=\"expirationDate\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Cognome\" Name=\"familyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice fiscale\" Name=\"fiscalNumber\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sesso\" Name=\"gender\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Documento d''identita\" Name=\"idCard\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Partita IVA\" Name=\"ivaCode\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Numero di telefono mobile\" Name=\"mobilePhone\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Nome\" Name=\"name\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Luogo di nascita\" Name=\"placeOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sede legale\" Name=\"registeredOffice\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice identificativo SPID\" Name=\"spidCode\"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"it\">https://www.infocert.it</md:OrganizationURL><md:OrganizationURL xml:lang=\"en\">https://www.infocert.it/international/?lang=en</md:OrganizationURL><md:OrganizationURL xml:lang=\"fr\">https://www.infocert.it/international/?lang=fr</md:OrganizationURL><md:OrganizationURL xml:lang=\"de\">https://www.infocert.it/international/?lang=de</md:OrganizationURL></md:Organization></md:EntityDescriptor>"
  },
  "apiVersion": "0.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (46, 'afd6c9e0-eeb5-4ca6-876c-86c984da8a6e', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 16:42:34.988713+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.1\" standalone=\"no\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"_25b183c4c721960977003fb04ec600b4\" cacheDuration=\"P0Y0M30DT0H0M0.000S\" entityID=\"https://identity.infocert.it\"><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"#_25b183c4c721960977003fb04ec600b4\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>hKbiiLWanDYNT69FQLh4uWlI6rVdAfoNXltq8WE83No=</DigestValue></Reference></SignedInfo><SignatureValue>nqWCyBqw40iHn3OEF9qVnJIzX9xmTzoq3EE9pbpPtrrAnjBWKTI2GxCAH84oD7BArJ/oBWOEQ0iJzFLwdtJK56ly8MwFAiYdCuNm9wHd03gSGBMxaWbhQSfwkwRCmMbzxcXJGMhh4JECOdZ87KR861A+S2EPyWBHC9yx8iRZ4UtmrGpf3UWyFJsCEjCLZv+a/ld6WnkP43OqJhs84BQWrH+Z1QOy1GDDYe+sItvQ1BhOomDT6x+ZsrMntgAItF+1kQxJ5CPRzGkYb10vr0WYukAAfcQ46fJ7Jje5ZBG8heBd61wxwKfuDDt6MD191PLWHjgy6sgA6zwXikGkQsTeeA==</SignatureValue><KeyInfo><X509Data><X509Certificate>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</X509Certificate></X509Data></KeyInfo></Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlsso\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlsso\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio fisico\" Name=\"address\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Ragione o denominazione sociale\" Name=\"companyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Provincia di nascita\" Name=\"countyOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di nascita\" Name=\"dateOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio digitale\" Name=\"digitalAddress\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Indirizzo di posta elettronica\" Name=\"email\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di scadenza identita\" Name=\"expirationDate\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Cognome\" Name=\"familyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice fiscale\" Name=\"fiscalNumber\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sesso\" Name=\"gender\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Documento d''identita\" Name=\"idCard\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Partita IVA\" Name=\"ivaCode\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Numero di telefono mobile\" Name=\"mobilePhone\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Nome\" Name=\"name\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Luogo di nascita\" Name=\"placeOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sede legale\" Name=\"registeredOffice\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice identificativo SPID\" Name=\"spidCode\"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"it\">https://www.infocert.it</md:OrganizationURL><md:OrganizationURL xml:lang=\"en\">https://www.infocert.it/international/?lang=en</md:OrganizationURL><md:OrganizationURL xml:lang=\"fr\">https://www.infocert.it/international/?lang=fr</md:OrganizationURL><md:OrganizationURL xml:lang=\"de\">https://www.infocert.it/international/?lang=de</md:OrganizationURL></md:Organization></md:EntityDescriptor>"
  },
  "apiVersion": "0.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (47, '2748daa3-c43b-4418-ac49-2875c9e99b42', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 16:43:13.204886+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\" standalone=\"no\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"_25b183c4c721960977003fb04ec600b4\" cacheDuration=\"P0Y0M30DT0H0M0.000S\" entityID=\"https://identity.infocert.it\"><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"#_25b183c4c721960977003fb04ec600b4\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>hKbiiLWanDYNT69FQLh4uWlI6rVdAfoNXltq8WE83No=</DigestValue></Reference></SignedInfo><SignatureValue>nqWCyBqw40iHn3OEF9qVnJIzX9xmTzoq3EE9pbpPtrrAnjBWKTI2GxCAH84oD7BArJ/oBWOEQ0iJzFLwdtJK56ly8MwFAiYdCuNm9wHd03gSGBMxaWbhQSfwkwRCmMbzxcXJGMhh4JECOdZ87KR861A+S2EPyWBHC9yx8iRZ4UtmrGpf3UWyFJsCEjCLZv+a/ld6WnkP43OqJhs84BQWrH+Z1QOy1GDDYe+sItvQ1BhOomDT6x+ZsrMntgAItF+1kQxJ5CPRzGkYb10vr0WYukAAfcQ46fJ7Jje5ZBG8heBd61wxwKfuDDt6MD191PLWHjgy6sgA6zwXikGkQsTeeA==</SignatureValue><KeyInfo><X509Data><X509Certificate>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</X509Certificate></X509Data></KeyInfo></Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlsso\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlsso\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio fisico\" Name=\"address\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Ragione o denominazione sociale\" Name=\"companyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Provincia di nascita\" Name=\"countyOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di nascita\" Name=\"dateOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio digitale\" Name=\"digitalAddress\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Indirizzo di posta elettronica\" Name=\"email\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di scadenza identita\" Name=\"expirationDate\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Cognome\" Name=\"familyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice fiscale\" Name=\"fiscalNumber\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sesso\" Name=\"gender\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Documento d''identita\" Name=\"idCard\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Partita IVA\" Name=\"ivaCode\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Numero di telefono mobile\" Name=\"mobilePhone\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Nome\" Name=\"name\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Luogo di nascita\" Name=\"placeOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sede legale\" Name=\"registeredOffice\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice identificativo SPID\" Name=\"spidCode\"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"fr\">InfoCer S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"it\">https://www.infocert.it</md:OrganizationURL><md:OrganizationURL xml:lang=\"en\">https://www.infocert.it/international/?lang=en</md:OrganizationURL><md:OrganizationURL xml:lang=\"fr\">https://www.infocert.it/international/?lang=fr</md:OrganizationURL><md:OrganizationURL xml:lang=\"de\">https://www.infocert.it/international/?lang=de</md:OrganizationURL></md:Organization></md:EntityDescriptor>"
  },
  "apiVersion": "0.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (48, '6323f881-c916-4cba-a211-6ff2929d9fdc', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 16:46:38.423806+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\"?>\n<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" entityID=\"https://identity.sieltecloud.it\" ID=\"pfxf9223e2d-feaf-64df-5f85-0836c6ae13bb\"><ds:Signature>\n  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n  <ds:Reference URI=\"#pfxf9223e2d-feaf-64df-5f85-0836c6ae13bb\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>RhsAXlUGQQjl9DbpeNUMvTrmVOv7rOhD179iyISRywM=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>wARTzsPTa9bh0p7pS523hkaqPvZ60kg2emtKWJZ61LUfYosOM1SZF9J0lDL9Oi8XWFyPBBCzbnQQiUC/7j1ju8Yj0rWvV9xCzrtsxyQFU+IhkiUgm2XuyG4IRZVFVgUTvyOXMf9lopBMeuAddgWIDpqZ6UidU/9pER/pHSM75FRuA+D1tIfOBvUuQ72NvfQ2Zy5VcRr57OdiTdr5sNMnPRUhVs5KRQMsLW6UumP9ciNsfjdw7cZTnKq5noyl/wsl06RXC31KnTtiM26MPAKFk+qVRPRrluJt+wxjBqy5Mbgbmve5ZKeZbb6HHctBSVHZYNlftVJxJi/EQ7lIYogPfg==</ds:SignatureValue>\n<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>\n  <md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" WantAuthnRequestsSigned=\"true\">\n    <md:KeyDescriptor use=\"signing\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:KeyDescriptor use=\"encryption\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SLS.php\"/>\n    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SLS.php\"/>\n    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php\"/>\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"familyName\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"name\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"spidCode\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"fiscalNumber\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"gender\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"dateOfBirth\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"placeOfBirth\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"companyName\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"registeredOffice\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"ivaCode\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"idCard\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"mobilePhone\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"email\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"address\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"digitalAddress\"/>\n  </md:IDPSSODescriptor>\n  <md:Organization>\n    <md:OrganizationName xml:lang=\"en\">Sielte S.p.A.</md:OrganizationName>\n    <md:OrganizationName xml:lang=\"it\">Sielte S.p.A.</md:OrganizationName>\n    <md:OrganizationDisplayName xml:lang=\"en\">http://www.sielte.it</md:OrganizationDisplayName>\n    <md:OrganizationDisplayName xml:lang=\"it\">http://www.sielte.it</md:OrganizationDisplayName>\n    <md:OrganizationURL xml:lang=\"en\">http://www.sielte.it</md:OrganizationURL>\n    <md:OrganizationURL xml:lang=\"it\">http://www.sielte.it</md:OrganizationURL>\n  </md:Organization>\n</md:EntityDescriptor>"
  },
  "apiVersion": "1.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (49, 'e4d1786c-7834-41e6-bf53-0ec3649abdb1', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 16:47:01.193678+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" entityID=\"https://identity.sieltecloud.it\" ID=\"pfxf9223e2d-feaf-64df-5f85-0836c6ae13bb\"><ds:Signature>\n  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n  <ds:Reference URI=\"#pfxf9223e2d-feaf-64df-5f85-0836c6ae13bb\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>RhsAXlUGQQjl9DbpeNUMvTrmVOv7rOhD179iyISRywM=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>wARTzsPTa9bh0p7pS523hkaqPvZ60kg2emtKWJZ61LUfYosOM1SZF9J0lDL9Oi8XWFyPBBCzbnQQiUC/7j1ju8Yj0rWvV9xCzrtsxyQFU+IhkiUgm2XuyG4IRZVFVgUTvyOXMf9lopBMeuAddgWIDpqZ6UidU/9pER/pHSM75FRuA+D1tIfOBvUuQ72NvfQ2Zy5VcRr57OdiTdr5sNMnPRUhVs5KRQMsLW6UumP9ciNsfjdw7cZTnKq5noyl/wsl06RXC31KnTtiM26MPAKFk+qVRPRrluJt+wxjBqy5Mbgbmve5ZKeZbb6HHctBSVHZYNlftVJxJi/EQ7lIYogPfg==</ds:SignatureValue>\n<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>\n  <md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" WantAuthnRequestsSigned=\"true\">\n    <md:KeyDescriptor use=\"signing\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:KeyDescriptor use=\"encryption\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SLS.php\"/>\n    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SLS.php\"/>\n    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php\"/>\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"familyName\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"name\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"spidCode\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"fiscalNumber\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"gender\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"dateOfBirth\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"placeOfBirth\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"companyName\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"registeredOffice\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"ivaCode\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"idCard\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"mobilePhone\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"email\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"address\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"digitalAddress\"/>\n  </md:IDPSSODescriptor>\n  <md:Organization>\n    <md:OrganizationName xml:lang=\"en\">Sielte S.p.A.</md:OrganizationName>\n    <md:OrganizationName xml:lang=\"it\">Sielte S.p.A.</md:OrganizationName>\n    <md:OrganizationDisplayName xml:lang=\"en\">http://www.sielte.it</md:OrganizationDisplayName>\n    <md:OrganizationDisplayName xml:lang=\"it\">http://www.sielte.it</md:OrganizationDisplayName>\n    <md:OrganizationURL xml:lang=\"en\">http://www.sielte.it</md:OrganizationURL>\n    <md:OrganizationURL xml:lang=\"it\">http://www.sielte.it</md:OrganizationURL>\n  </md:Organization>\n</md:EntityDescriptor>"
  },
  "apiVersion": "1.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (50, 'cc9e8564-269e-4be0-9e6c-156f63733ac3', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 16:47:17.998761+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\"?>\n<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" entityID=\"https://identity.sieltecloud.it\" ID=\"pfxf9223e2d-feaf-64df-5f85-0836c6ae13ba\"><ds:Signature>\n  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n  <ds:Reference URI=\"#pfxf9223e2d-feaf-64df-5f85-0836c6ae13bb\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>RhsAXlUGQQjl9DbpeNUMvTrmVOv7rOhD179iyISRywM=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>wARTzsPTa9bh0p7pS523hkaqPvZ60kg2emtKWJZ61LUfYosOM1SZF9J0lDL9Oi8XWFyPBBCzbnQQiUC/7j1ju8Yj0rWvV9xCzrtsxyQFU+IhkiUgm2XuyG4IRZVFVgUTvyOXMf9lopBMeuAddgWIDpqZ6UidU/9pER/pHSM75FRuA+D1tIfOBvUuQ72NvfQ2Zy5VcRr57OdiTdr5sNMnPRUhVs5KRQMsLW6UumP9ciNsfjdw7cZTnKq5noyl/wsl06RXC31KnTtiM26MPAKFk+qVRPRrluJt+wxjBqy5Mbgbmve5ZKeZbb6HHctBSVHZYNlftVJxJi/EQ7lIYogPfg==</ds:SignatureValue>\n<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>\n  <md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" WantAuthnRequestsSigned=\"true\">\n    <md:KeyDescriptor use=\"signing\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:KeyDescriptor use=\"encryption\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SLS.php\"/>\n    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SLS.php\"/>\n    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php\"/>\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"familyName\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"name\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"spidCode\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"fiscalNumber\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"gender\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"dateOfBirth\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"placeOfBirth\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"companyName\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"registeredOffice\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"ivaCode\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"idCard\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"mobilePhone\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"email\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"address\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"digitalAddress\"/>\n  </md:IDPSSODescriptor>\n  <md:Organization>\n    <md:OrganizationName xml:lang=\"en\">Sielte S.p.A.</md:OrganizationName>\n    <md:OrganizationName xml:lang=\"it\">Sielte S.p.A.</md:OrganizationName>\n    <md:OrganizationDisplayName xml:lang=\"en\">http://www.sielte.it</md:OrganizationDisplayName>\n    <md:OrganizationDisplayName xml:lang=\"it\">http://www.sielte.it</md:OrganizationDisplayName>\n    <md:OrganizationURL xml:lang=\"en\">http://www.sielte.it</md:OrganizationURL>\n    <md:OrganizationURL xml:lang=\"it\">http://www.sielte.it</md:OrganizationURL>\n  </md:Organization>\n</md:EntityDescriptor>"
  },
  "apiVersion": "1.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (51, 'a132a05c-d5cc-426f-a207-902ee1a49bc1', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 16:47:29.043021+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\"?>\n<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" entityID=\"https://identity.sieltecloud.it\" ID=\"pfxf9223e2d-feaf-64df-5f85-0836c6ae13bb\"><ds:Signature>\n  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n  <ds:Reference URI=\"#pfxf9223e2d-feaf-64df-5f85-0836c6ae13bb\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>RhsAXlUGQQjl9DbpeNUMvTrmVOv7rOhD179iyISRywM=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>wARTzsPTa9bh0p7pS523hkaqPvZ60kg2emtKWJZ61LUfYosOM1SZF9J0lDL9Oi8XWFyPBBCzbnQQiUC/7j1ju8Yj0rWvV9xCzrtsxyQFU+IhkiUgm2XuyG4IRZVFVgUTvyOXMf9lopBMeuAddgWIDpqZ6UidU/9pER/pHSM75FRuA+D1tIfOBvUuQ72NvfQ2Zy5VcRr57OdiTdr5sNMnPRUhVs5KRQMsLW6UumP9ciNsfjdw7cZTnKq5noyl/wsl06RXC31KnTtiM26MPAKFk+qVRPRrluJt+wxjBqy5Mbgbmve5ZKeZbb6HHctBSVHZYNlftVJxJi/EQ7lIYogPfg==</ds:SignatureValue>\n<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>\n  <md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" WantAuthnRequestsSigned=\"true\">\n    <md:KeyDescriptor use=\"signing\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:KeyDescriptor use=\"encryption\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SLS.php\"/>\n    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SLS.php\"/>\n    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php\"/>\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"familyName\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"name\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"spidCode\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"fiscalNumber\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"gender\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"dateOfBirth\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"placeOfBirth\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"companyName\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"registeredOffice\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"ivaCode\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"idCard\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"mobilePhone\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"email\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"address\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"digitalAddress\"/>\n  </md:IDPSSODescriptor>\n  <md:Organization>\n    <md:OrganizationName xml:lang=\"en\">Sielte S.p.A.</md:OrganizationName>\n    <md:OrganizationName xml:lang=\"it\">Sielte S.p.A.</md:OrganizationName>\n    <md:OrganizationDisplayName xml:lang=\"en\">http://www.sielte.it</md:OrganizationDisplayName>\n    <md:OrganizationDisplayName xml:lang=\"it\">http://www.sielte.it</md:OrganizationDisplayName>\n    <md:OrganizationURL xml:lang=\"en\">http://www.sielte.it</md:OrganizationURL>\n    <md:OrganizationURL xml:lang=\"it\">http://www.sielte.it</md:OrganizationURL>\n  </md:Organization>\n</md:EntityDescriptor>"
  },
  "apiVersion": "1.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (52, 'ac7b2713-04ad-4b7b-ac59-1a3b84d3d1bc', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 17:02:51.612265+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\"?>\n<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" entityID=\"https://identity.sieltecloud.it\" ID=\"pfxf9223e2d-feaf-64df-5f85-0836c6ae13bb\"><ds:Signature>\n  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n  <ds:Reference URI=\"#pfxf9223e2d-feaf-64df-5f85-0836c6ae13bb\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>RhsAXlUGQQjl9DbpeNUMvTrmVOv7rOhD179iyISRywM=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>wARTzsPTa9bh0p7pS523hkaqPvZ60kg2emtKWJZ61LUfYosOM1SZF9J0lDL9Oi8XWFyPBBCzbnQQiUC/7j1ju8Yj0rWvV9xCzrtsxyQFU+IhkiUgm2XuyG4IRZVFVgUTvyOXMf9lopBMeuAddgWIDpqZ6UidU/9pER/pHSM75FRuA+D1tIfOBvUuQ72NvfQ2Zy5VcRr57OdiTdr5sNMnPRUhVs5KRQMsLW6UumP9ciNsfjdw7cZTnKq5noyl/wsl06RXC31KnTtiM26MPAKFk+qVRPRrluJt+wxjBqy5Mbgbmve5ZKeZbb6HHctBSVHZYNlftVJxJi/EQ7lIYogPfg==</ds:SignatureValue>\n<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>\n  <md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" WantAuthnRequestsSigned=\"true\">\n    <md:KeyDescriptor use=\"signing\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:KeyDescriptor use=\"encryption\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SLS.php\"/>\n    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SLS.php\"/>\n    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php\"/>\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"familyName\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"name\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"spidCode\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"fiscalNumber\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"gender\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"dateOfBirth\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"placeOfBirth\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"companyName\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"registeredOffice\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"ivaCode\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"idCard\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"mobilePhone\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"email\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"address\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"digitalAddress\"/>\n  </md:IDPSSODescriptor>\n  <md:Organization>\n    <md:OrganizationName xml:lang=\"en\">Sielte S.p.A.</md:OrganizationName>\n    <md:OrganizationName xml:lang=\"it\">Sielte S.p.A.</md:OrganizationName>\n    <md:OrganizationDisplayName xml:lang=\"en\">http://www.sielte.it</md:OrganizationDisplayName>\n    <md:OrganizationDisplayName xml:lang=\"it\">http://www.sielte.it</md:OrganizationDisplayName>\n    <md:OrganizationURL xml:lang=\"en\">http://www.sielte.it</md:OrganizationURL>\n    <md:OrganizationURL xml:lang=\"it\">http://www.sielte.it</md:OrganizationURL>\n  </md:Organization>\n</md:EntityDescriptor>"
  },
  "apiVersion": "1.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (53, 'c6f0f966-a275-4db7-bc04-be417703e262', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 17:03:19.749461+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\"?>\n<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" entityID=\"https://identity.sieltecloud.it\" ID=\"pfxf9223e2d-feaf-64df-5f85-0836c6ae13bb\"><ds:Signature>\n  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n  <ds:Reference URI=\"#pfxf9223e2d-feaf-64df-5f85-0836c6ae13bb\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>RhsAXlUGQQjl9DbpeNUMvTrmVOv7rOhD179iyISRywM=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>wARTzsPTa9bh0p7pS523hkaqPvZ60kg2emtKWJZ61LUfYosOM1SZF9J0lDL9Oi8XWFyPBBCzbnQQiUC/7j1ju8Yj0rWvV9xCzrtsxyQFU+IhkiUgm2XuyG4IRZVFVgUTvyOXMf9lopBMeuAddgWIDpqZ6UidU/9pER/pHSM75FRuA+D1tIfOBvUuQ72NvfQ2Zy5VcRr57OdiTdr5sNMnPRUhVs5KRQMsLW6UumP9ciNsfjdw7cZTnKq5noyl/wsl06RXC31KnTtiM26MPAKFk+qVRPRrluJt+wxjBqy5Mbgbmve5ZKeZbb6HHctBSVHZYNlftVJxJi/EQ7lIYogPfg==</ds:SignatureValue>\n<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>\n  <md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" WantAuthnRequestsSigned=\"true\">\n    <md:KeyDescriptor use=\"signing\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:KeyDescriptor use=\"encryption\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SLS.php\"/>\n    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SLS.php\"/>\n    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php\"/>\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"familyName\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"name\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"spidCode\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"fiscalNumber\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"gender\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"dateOfBirth\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"placeOfBirth\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"companyName\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"registeredOffice\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"ivaCode\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"idCard\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"mobilePhone\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"email\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"address\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"digitalAddress\"/>\n  </md:IDPSSODescriptor>\n  <md:Organization>\n    <md:OrganizationName xml:lang=\"en\">Sielte S.p.A.</md:OrganizationName>\n    <md:OrganizationName xml:lang=\"it\">Sielte S.p.A.</md:OrganizationName>\n    <md:OrganizationDisplayName xml:lang=\"en\">http://www.sielte.it</md:OrganizationDisplayName>\n    <md:OrganizationDisplayName xml:lang=\"it\">http://www.sielte.it</md:OrganizationDisplayName>\n    <md:OrganizationURL xml:lang=\"en\">http://www.sielte.it</md:OrganizationURL>\n    <md:OrganizationURL xml:lang=\"it\">http://www.sielte.it</md:OrganizationURL>\n  </md:Organization>\n</md:EntityDescriptor>"
  },
  "apiVersion": "1.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (54, '7edee511-1d79-4ebe-a4ca-eac644797a53', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 17:08:27.162426+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\"?>\n<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" entityID=\"https://identity.sieltecloud.it\" ID=\"pfxf9223e2d-feaf-64df-5f85-0836c6ae13bb\"><ds:Signature>\n  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n  <ds:Reference URI=\"#pfxf9223e2d-feaf-64df-5f85-0836c6ae13bb\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>RhsAXlUGQQjl9DbpeNUMvTrmVOv7rOhD179iyISRywM=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>wARTzsPTa9bh0p7pS523hkaqPvZ60kg2emtKWJZ61LUfYosOM1SZF9J0lDL9Oi8XWFyPBBCzbnQQiUC/7j1ju8Yj0rWvV9xCzrtsxyQFU+IhkiUgm2XuyG4IRZVFVgUTvyOXMf9lopBMeuAddgWIDpqZ6UidU/9pER/pHSM75FRuA+D1tIfOBvUuQ72NvfQ2Zy5VcRr57OdiTdr5sNMnPRUhVs5KRQMsLW6UumP9ciNsfjdw7cZTnKq5noyl/wsl06RXC31KnTtiM26MPAKFk+qVRPRrluJt+wxjBqy5Mbgbmve5ZKeZbb6HHctBSVHZYNlftVJxJi/EQ7lIYogPfg==</ds:SignatureValue>\n<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>\n  <md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" WantAuthnRequestsSigned=\"true\">\n    <md:KeyDescriptor use=\"signing\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:KeyDescriptor use=\"encryption\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SLS.php\"/>\n    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SLS.php\"/>\n    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php\"/>\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"familyName\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"name\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"spidCode\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"fiscalNumber\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"gender\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"dateOfBirth\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"placeOfBirth\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"companyName\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"registeredOffice\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"ivaCode\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"idCard\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"mobilePhone\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"email\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"address\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"digitalAddress\"/>\n  </md:IDPSSODescriptor>\n  <md:Organization>\n    <md:OrganizationName xml:lang=\"en\">Sielte S.p.A.</md:OrganizationName>\n    <md:OrganizationName xml:lang=\"it\">Sielte S.p.A.</md:OrganizationName>\n    <md:OrganizationDisplayName xml:lang=\"en\">http://www.sielte.it</md:OrganizationDisplayName>\n    <md:OrganizationDisplayName xml:lang=\"it\">http://www.sielte.it</md:OrganizationDisplayName>\n    <md:OrganizationURL xml:lang=\"en\">http://www.sielte.it</md:OrganizationURL>\n    <md:OrganizationURL xml:lang=\"it\">http://www.sielte.it</md:OrganizationURL>\n  </md:Organization>\n</md:EntityDescriptor>",
    "provider": "sapienza"
  },
  "apiVersion": "1.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (55, 'e6353fb0-b2a8-42ab-b47f-ae80898613ee', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 17:09:57.1505+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\"?>\n<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" entityID=\"https://identity.sieltecloud.it\" ID=\"pfxf9223e2d-feaf-64df-5f85-0836c6ae13bb\"><ds:Signature>\n  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n  <ds:Reference URI=\"#pfxf9223e2d-feaf-64df-5f85-0836c6ae13bb\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>RhsAXlUGQQjl9DbpeNUMvTrmVOv7rOhD179iyISRywM=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>wARTzsPTa9bh0p7pS523hkaqPvZ60kg2emtKWJZ61LUfYosOM1SZF9J0lDL9Oi8XWFyPBBCzbnQQiUC/7j1ju8Yj0rWvV9xCzrtsxyQFU+IhkiUgm2XuyG4IRZVFVgUTvyOXMf9lopBMeuAddgWIDpqZ6UidU/9pER/pHSM75FRuA+D1tIfOBvUuQ72NvfQ2Zy5VcRr57OdiTdr5sNMnPRUhVs5KRQMsLW6UumP9ciNsfjdw7cZTnKq5noyl/wsl06RXC31KnTtiM26MPAKFk+qVRPRrluJt+wxjBqy5Mbgbmve5ZKeZbb6HHctBSVHZYNlftVJxJi/EQ7lIYogPfg==</ds:SignatureValue>\n<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>\n  <md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" WantAuthnRequestsSigned=\"true\">\n    <md:KeyDescriptor use=\"signing\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:KeyDescriptor use=\"encryption\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SLS.php\"/>\n    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SLS.php\"/>\n    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php\"/>\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"familyName\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"name\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"spidCode\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"fiscalNumber\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"gender\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"dateOfBirth\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"placeOfBirth\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"companyName\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"registeredOffice\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"ivaCode\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"idCard\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"mobilePhone\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"email\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"address\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"digitalAddress\"/>\n  </md:IDPSSODescriptor>\n  <md:Organization>\n    <md:OrganizationName xml:lang=\"en\">Sielte S.p.A.</md:OrganizationName>\n    <md:OrganizationName xml:lang=\"it\">Sielte S.p.A.</md:OrganizationName>\n    <md:OrganizationDisplayName xml:lang=\"en\">http://www.sielte.it</md:OrganizationDisplayName>\n    <md:OrganizationDisplayName xml:lang=\"it\">http://www.sielte.it</md:OrganizationDisplayName>\n    <md:OrganizationURL xml:lang=\"en\">http://www.sielte.it</md:OrganizationURL>\n    <md:OrganizationURL xml:lang=\"it\">http://www.sielte.it</md:OrganizationURL>\n  </md:Organization>\n</md:EntityDescriptor>",
    "provider": "sapienza"
  },
  "apiVersion": "1.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (56, '8cb20268-fe01-4c7b-8d4e-04ac26b5f97a', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 17:11:04.716596+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\"?>\n<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" entityID=\"https://identity.sieltecloud.it\" ID=\"pfxf9223e2d-feaf-64df-5f85-0836c6ae13bb\"><ds:Signature>\n  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n  <ds:Reference URI=\"#pfxf9223e2d-feaf-64df-5f85-0836c6ae13bb\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>RhsAXlUGQQjl9DbpeNUMvTrmVOv7rOhD179iyISRywM=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>wARTzsPTa9bh0p7pS523hkaqPvZ60kg2emtKWJZ61LUfYosOM1SZF9J0lDL9Oi8XWFyPBBCzbnQQiUC/7j1ju8Yj0rWvV9xCzrtsxyQFU+IhkiUgm2XuyG4IRZVFVgUTvyOXMf9lopBMeuAddgWIDpqZ6UidU/9pER/pHSM75FRuA+D1tIfOBvUuQ72NvfQ2Zy5VcRr57OdiTdr5sNMnPRUhVs5KRQMsLW6UumP9ciNsfjdw7cZTnKq5noyl/wsl06RXC31KnTtiM26MPAKFk+qVRPRrluJt+wxjBqy5Mbgbmve5ZKeZbb6HHctBSVHZYNlftVJxJi/EQ7lIYogPfg==</ds:SignatureValue>\n<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>\n  <md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" WantAuthnRequestsSigned=\"true\">\n    <md:KeyDescriptor use=\"signing\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:KeyDescriptor use=\"encryption\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SLS.php\"/>\n    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SLS.php\"/>\n    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php\"/>\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"familyName\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"name\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"spidCode\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"fiscalNumber\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"gender\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"dateOfBirth\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"placeOfBirth\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"companyName\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"registeredOffice\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"ivaCode\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"idCard\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"mobilePhone\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"email\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"address\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"digitalAddress\"/>\n  </md:IDPSSODescriptor>\n  <md:Organization>\n    <md:OrganizationName xml:lang=\"en\">Sielte S.p.A.</md:OrganizationName>\n    <md:OrganizationName xml:lang=\"it\">Sielte S.p.A.</md:OrganizationName>\n    <md:OrganizationDisplayName xml:lang=\"en\">http://www.sielte.it</md:OrganizationDisplayName>\n    <md:OrganizationDisplayName xml:lang=\"it\">http://www.sielte.it</md:OrganizationDisplayName>\n    <md:OrganizationURL xml:lang=\"en\">http://www.sielte.it</md:OrganizationURL>\n    <md:OrganizationURL xml:lang=\"it\">http://www.sielte.it</md:OrganizationURL>\n  </md:Organization>\n</md:EntityDescriptor>",
    "provider": "sapienza"
  },
  "apiVersion": "1.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (57, '7e68e8ed-f862-4a7c-a387-b59e0a61237a', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 17:11:17.019518+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\"?>\n<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" entityID=\"https://identity.sieltecloud.it\" ID=\"pfxf9223e2d-feaf-64df-5f85-0836c6ae13bb\"><ds:Signature>\n  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n  <ds:Reference URI=\"#pfxf9223e2d-feaf-64df-5f85-0836c6ae13bb\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>RhsAXlUGQQjl9DbpeNUMvTrmVOv7rOhD179iyISRywM=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>wARTzsPTa9bh0p7pS523hkaqPvZ60kg2emtKWJZ61LUfYosOM1SZF9J0lDL9Oi8XWFyPBBCzbnQQiUC/7j1ju8Yj0rWvV9xCzrtsxyQFU+IhkiUgm2XuyG4IRZVFVgUTvyOXMf9lopBMeuAddgWIDpqZ6UidU/9pER/pHSM75FRuA+D1tIfOBvUuQ72NvfQ2Zy5VcRr57OdiTdr5sNMnPRUhVs5KRQMsLW6UumP9ciNsfjdw7cZTnKq5noyl/wsl06RXC31KnTtiM26MPAKFk+qVRPRrluJt+wxjBqy5Mbgbmve5ZKeZbb6HHctBSVHZYNlftVJxJi/EQ7lIYogPfg==</ds:SignatureValue>\n<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>\n  <md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" WantAuthnRequestsSigned=\"true\">\n    <md:KeyDescriptor use=\"signing\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:KeyDescriptor use=\"encryption\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SLS.php\"/>\n    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SLS.php\"/>\n    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php\"/>\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"familyName\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"name\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"spidCode\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"fiscalNumber\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"gender\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"dateOfBirth\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"placeOfBirth\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"companyName\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"registeredOffice\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"ivaCode\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"idCard\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"mobilePhone\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"email\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"address\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"digitalAddress\"/>\n  </md:IDPSSODescriptor>\n  <md:Organization>\n    <md:OrganizationName xml:lang=\"en\">Sielte S.p.A.</md:OrganizationName>\n    <md:OrganizationName xml:lang=\"it\">Sielte S.p.A.</md:OrganizationName>\n    <md:OrganizationDisplayName xml:lang=\"en\">http://www.sielte.it</md:OrganizationDisplayName>\n    <md:OrganizationDisplayName xml:lang=\"it\">http://www.sielte.it</md:OrganizationDisplayName>\n    <md:OrganizationURL xml:lang=\"en\">http://www.sielte.it</md:OrganizationURL>\n    <md:OrganizationURL xml:lang=\"it\">http://www.sielte.it</md:OrganizationURL>\n  </md:Organization>\n</md:EntityDescriptor>",
    "provider": "sielte"
  },
  "apiVersion": "1.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (58, 'b96a0e59-833c-4e56-bb3d-251b07c09f5d', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 17:17:08.525002+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\"?>\n<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" entityID=\"https://identity.sieltecloud.it\" ID=\"pfxf9223e2d-feaf-64df-5f85-0836c6ae13bb\"><ds:Signature>\n  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n  <ds:Reference URI=\"#pfxf9223e2d-feaf-64df-5f85-0836c6ae13bb\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>RhsAXlUGQQjl9DbpeNUMvTrmVOv7rOhD179iyISRywM=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>wARTzsPTa9bh0p7pS523hkaqPvZ60kg2emtKWJZ61LUfYosOM1SZF9J0lDL9Oi8XWFyPBBCzbnQQiUC/7j1ju8Yj0rWvV9xCzrtsxyQFU+IhkiUgm2XuyG4IRZVFVgUTvyOXMf9lopBMeuAddgWIDpqZ6UidU/9pER/pHSM75FRuA+D1tIfOBvUuQ72NvfQ2Zy5VcRr57OdiTdr5sNMnPRUhVs5KRQMsLW6UumP9ciNsfjdw7cZTnKq5noyl/wsl06RXC31KnTtiM26MPAKFk+qVRPRrluJt+wxjBqy5Mbgbmve5ZKeZbb6HHctBSVHZYNlftVJxJi/EQ7lIYogPfg==</ds:SignatureValue>\n<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>\n  <md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" WantAuthnRequestsSigned=\"true\">\n    <md:KeyDescriptor use=\"signing\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:KeyDescriptor use=\"encryption\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SLS.php\"/>\n    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SLS.php\"/>\n    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php\"/>\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"familyName\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"name\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"spidCode\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"fiscalNumber\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"gender\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"dateOfBirth\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"placeOfBirth\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"companyName\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"registeredOffice\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"ivaCode\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"idCard\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"mobilePhone\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"email\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"address\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"digitalAddress\"/>\n  </md:IDPSSODescriptor>\n  <md:Organization>\n    <md:OrganizationName xml:lang=\"en\">Sielte S.p.A.</md:OrganizationName>\n    <md:OrganizationName xml:lang=\"it\">Sielte S.p.A.</md:OrganizationName>\n    <md:OrganizationDisplayName xml:lang=\"en\">http://www.sielte.it</md:OrganizationDisplayName>\n    <md:OrganizationDisplayName xml:lang=\"it\">http://www.sielte.it</md:OrganizationDisplayName>\n    <md:OrganizationURL xml:lang=\"en\">http://www.sielte.it</md:OrganizationURL>\n    <md:OrganizationURL xml:lang=\"it\">http://www.sielte.it</md:OrganizationURL>\n  </md:Organization>\n</md:EntityDescriptor>",
    "provider": "sielte"
  },
  "apiVersion": "1.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (59, '4eb07fb8-1c91-445d-97b2-58ca34198e37', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 17:17:17.904506+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\"?>\n<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" entityID=\"https://identity.sieltecloud.it\" ID=\"pfxf9223e2d-feaf-64df-5f85-0836c6ae13bb\"><ds:Signature>\n  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n  <ds:Reference URI=\"#pfxf9223e2d-feaf-64df-5f85-0836c6ae13bb\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>RhsAXlUGQQjl9DbpeNUMvTrmVOv7rOhD179iyISRywM=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>wARTzsPTa9bh0p7pS523hkaqPvZ60kg2emtKWJZ61LUfYosOM1SZF9J0lDL9Oi8XWFyPBBCzbnQQiUC/7j1ju8Yj0rWvV9xCzrtsxyQFU+IhkiUgm2XuyG4IRZVFVgUTvyOXMf9lopBMeuAddgWIDpqZ6UidU/9pER/pHSM75FRuA+D1tIfOBvUuQ72NvfQ2Zy5VcRr57OdiTdr5sNMnPRUhVs5KRQMsLW6UumP9ciNsfjdw7cZTnKq5noyl/wsl06RXC31KnTtiM26MPAKFk+qVRPRrluJt+wxjBqy5Mbgbmve5ZKeZbb6HHctBSVHZYNlftVJxJi/EQ7lIYogPfg==</ds:SignatureValue>\n<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>\n  <md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" WantAuthnRequestsSigned=\"true\">\n    <md:KeyDescriptor use=\"signing\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:KeyDescriptor use=\"encryption\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SLS.php\"/>\n    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SLS.php\"/>\n    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php\"/>\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"familyName\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"name\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"spidCode\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"fiscalNumber\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"gender\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"dateOfBirth\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"placeOfBirth\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"companyName\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"registeredOffice\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"ivaCode\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"idCard\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"mobilePhone\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"email\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"address\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"digitalAddress\"/>\n  </md:IDPSSODescriptor>\n  <md:Organization>\n    <md:OrganizationName xml:lang=\"en\">Sielte S.p.A.</md:OrganizationName>\n    <md:OrganizationName xml:lang=\"it\">Sielte S.p.A.</md:OrganizationName>\n    <md:OrganizationDisplayName xml:lang=\"en\">http://www.sielte.it</md:OrganizationDisplayName>\n    <md:OrganizationDisplayName xml:lang=\"it\">http://www.sielte.it</md:OrganizationDisplayName>\n    <md:OrganizationURL xml:lang=\"en\">http://www.sielte.it</md:OrganizationURL>\n    <md:OrganizationURL xml:lang=\"it\">http://www.sielte.it</md:OrganizationURL>\n  </md:Organization>\n</md:EntityDescriptor>",
    "provider": "sapienza"
  },
  "apiVersion": "1.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (60, '95136882-74bb-43a0-87f0-aeb7c8942956', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 17:17:24.228167+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\"?>\n<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" entityID=\"https://identity.sieltecloud.it\" ID=\"pfxf9223e2d-feaf-64df-5f85-0836c6ae13bb\"><ds:Signature>\n  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n  <ds:Reference URI=\"#pfxf9223e2d-feaf-64df-5f85-0836c6ae13bb\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>RhsAXlUGQQjl9DbpeNUMvTrmVOv7rOhD179iyISRywM=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>wARTzsPTa9bh0p7pS523hkaqPvZ60kg2emtKWJZ61LUfYosOM1SZF9J0lDL9Oi8XWFyPBBCzbnQQiUC/7j1ju8Yj0rWvV9xCzrtsxyQFU+IhkiUgm2XuyG4IRZVFVgUTvyOXMf9lopBMeuAddgWIDpqZ6UidU/9pER/pHSM75FRuA+D1tIfOBvUuQ72NvfQ2Zy5VcRr57OdiTdr5sNMnPRUhVs5KRQMsLW6UumP9ciNsfjdw7cZTnKq5noyl/wsl06RXC31KnTtiM26MPAKFk+qVRPRrluJt+wxjBqy5Mbgbmve5ZKeZbb6HHctBSVHZYNlftVJxJi/EQ7lIYogPfg==</ds:SignatureValue>\n<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>\n  <md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" WantAuthnRequestsSigned=\"true\">\n    <md:KeyDescriptor use=\"signing\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:KeyDescriptor use=\"encryption\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SLS.php\"/>\n    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SLS.php\"/>\n    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php\"/>\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"familyName\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"name\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"spidCode\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"fiscalNumber\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"gender\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"dateOfBirth\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"placeOfBirth\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"companyName\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"registeredOffice\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"ivaCode\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"idCard\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"mobilePhone\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"email\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"address\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"digitalAddress\"/>\n  </md:IDPSSODescriptor>\n  <md:Organization>\n    <md:OrganizationName xml:lang=\"en\">Sielte S.p.A.</md:OrganizationName>\n    <md:OrganizationName xml:lang=\"it\">Sielte S.p.A.</md:OrganizationName>\n    <md:OrganizationDisplayName xml:lang=\"en\">http://www.sielte.it</md:OrganizationDisplayName>\n    <md:OrganizationDisplayName xml:lang=\"it\">http://www.sielte.it</md:OrganizationDisplayName>\n    <md:OrganizationURL xml:lang=\"en\">http://www.sielte.it</md:OrganizationURL>\n    <md:OrganizationURL xml:lang=\"it\">http://www.sielte.it</md:OrganizationURL>\n  </md:Organization>\n</md:EntityDescriptor>",
    "provider": "asd"
  },
  "apiVersion": "1.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (61, 'c051445b-b7cb-4a2d-b802-c7f7c644fba8', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 17:19:37.515681+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\"?>\n<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" entityID=\"https://identity.sieltecloud.it\" ID=\"pfxf9223e2d-feaf-64df-5f85-0836c6ae13bb\"><ds:Signature>\n  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n  <ds:Reference URI=\"#pfxf9223e2d-feaf-64df-5f85-0836c6ae13bb\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>RhsAXlUGQQjl9DbpeNUMvTrmVOv7rOhD179iyISRywM=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>wARTzsPTa9bh0p7pS523hkaqPvZ60kg2emtKWJZ61LUfYosOM1SZF9J0lDL9Oi8XWFyPBBCzbnQQiUC/7j1ju8Yj0rWvV9xCzrtsxyQFU+IhkiUgm2XuyG4IRZVFVgUTvyOXMf9lopBMeuAddgWIDpqZ6UidU/9pER/pHSM75FRuA+D1tIfOBvUuQ72NvfQ2Zy5VcRr57OdiTdr5sNMnPRUhVs5KRQMsLW6UumP9ciNsfjdw7cZTnKq5noyl/wsl06RXC31KnTtiM26MPAKFk+qVRPRrluJt+wxjBqy5Mbgbmve5ZKeZbb6HHctBSVHZYNlftVJxJi/EQ7lIYogPfg==</ds:SignatureValue>\n<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>\n  <md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" WantAuthnRequestsSigned=\"true\">\n    <md:KeyDescriptor use=\"signing\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:KeyDescriptor use=\"encryption\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SLS.php\"/>\n    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SLS.php\"/>\n    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php\"/>\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"familyName\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"name\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"spidCode\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"fiscalNumber\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"gender\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"dateOfBirth\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"placeOfBirth\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"companyName\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"registeredOffice\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"ivaCode\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"idCard\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"mobilePhone\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"email\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"address\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"digitalAddress\"/>\n  </md:IDPSSODescriptor>\n  <md:Organization>\n    <md:OrganizationName xml:lang=\"en\">Sielte S.p.A.</md:OrganizationName>\n    <md:OrganizationName xml:lang=\"it\">Sielte S.p.A.</md:OrganizationName>\n    <md:OrganizationDisplayName xml:lang=\"en\">http://www.sielte.it</md:OrganizationDisplayName>\n    <md:OrganizationDisplayName xml:lang=\"it\">http://www.sielte.it</md:OrganizationDisplayName>\n    <md:OrganizationURL xml:lang=\"en\">http://www.sielte.it</md:OrganizationURL>\n    <md:OrganizationURL xml:lang=\"it\">http://www.sielte.it</md:OrganizationURL>\n  </md:Organization>\n</md:EntityDescriptor>",
    "provider": "asd"
  },
  "apiVersion": "1.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (62, '21e94486-5920-4f21-9cc7-3804bad80af4', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 17:20:03.606068+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\"?>\n<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" entityID=\"https://identity.sieltecloud.it\" ID=\"pfxf9223e2d-feaf-64df-5f85-0836c6ae13bb\"><ds:Signature>\n  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n  <ds:Reference URI=\"#pfxf9223e2d-feaf-64df-5f85-0836c6ae13bb\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>RhsAXlUGQQjl9DbpeNUMvTrmVOv7rOhD179iyISRywM=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>wARTzsPTa9bh0p7pS523hkaqPvZ60kg2emtKWJZ61LUfYosOM1SZF9J0lDL9Oi8XWFyPBBCzbnQQiUC/7j1ju8Yj0rWvV9xCzrtsxyQFU+IhkiUgm2XuyG4IRZVFVgUTvyOXMf9lopBMeuAddgWIDpqZ6UidU/9pER/pHSM75FRuA+D1tIfOBvUuQ72NvfQ2Zy5VcRr57OdiTdr5sNMnPRUhVs5KRQMsLW6UumP9ciNsfjdw7cZTnKq5noyl/wsl06RXC31KnTtiM26MPAKFk+qVRPRrluJt+wxjBqy5Mbgbmve5ZKeZbb6HHctBSVHZYNlftVJxJi/EQ7lIYogPfg==</ds:SignatureValue>\n<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>\n  <md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" WantAuthnRequestsSigned=\"true\">\n    <md:KeyDescriptor use=\"signing\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:KeyDescriptor use=\"encryption\">\n      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n        <ds:X509Data>\n          <ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n    </md:KeyDescriptor>\n    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SLS.php\"/>\n    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SLS.php\"/>\n    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php\"/>\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"familyName\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"name\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"spidCode\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"fiscalNumber\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"gender\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"dateOfBirth\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"placeOfBirth\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"companyName\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"registeredOffice\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"ivaCode\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"idCard\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"mobilePhone\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"email\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"address\"/>\n    <saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"digitalAddress\"/>\n  </md:IDPSSODescriptor>\n  <md:Organization>\n    <md:OrganizationName xml:lang=\"en\">Sielte S.p.A.</md:OrganizationName>\n    <md:OrganizationName xml:lang=\"it\">Sielte S.p.A.</md:OrganizationName>\n    <md:OrganizationDisplayName xml:lang=\"en\">http://www.sielte.it</md:OrganizationDisplayName>\n    <md:OrganizationDisplayName xml:lang=\"it\">http://www.sielte.it</md:OrganizationDisplayName>\n    <md:OrganizationURL xml:lang=\"en\">http://www.sielte.it</md:OrganizationURL>\n    <md:OrganizationURL xml:lang=\"it\">http://www.sielte.it</md:OrganizationURL>\n  </md:Organization>\n</md:EntityDescriptor>",
    "provider": ""
  },
  "apiVersion": "1.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (63, 'e06ee7e7-d228-44bb-b204-ae909809a0ca', 'GET', 'http://192.168.56.103:8888/api/prvd/infocrt/metadata', '2017-07-24 17:21:23.6068+02', '192.168.56.1', NULL);
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (64, 'b33589c5-2185-4617-b17c-793a8e7016ba', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 17:21:46.571399+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\" standalone=\"no\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"_25b183c4c721960977003fb04ec600b4\" cacheDuration=\"P0Y0M30DT0H0M0.000S\" entityID=\"https://identity.infocert.it\"><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"#_25b183c4c721960977003fb04ec600b4\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>hKbiiLWanDYNT69FQLh4uWlI6rVdAfoNXltq8WE83No=</DigestValue></Reference></SignedInfo><SignatureValue>nqWCyBqw40iHn3OEF9qVnJIzX9xmTzoq3EE9pbpPtrrAnjBWKTI2GxCAH84oD7BArJ/oBWOEQ0iJzFLwdtJK56ly8MwFAiYdCuNm9wHd03gSGBMxaWbhQSfwkwRCmMbzxcXJGMhh4JECOdZ87KR861A+S2EPyWBHC9yx8iRZ4UtmrGpf3UWyFJsCEjCLZv+a/ld6WnkP43OqJhs84BQWrH+Z1QOy1GDDYe+sItvQ1BhOomDT6x+ZsrMntgAItF+1kQxJ5CPRzGkYb10vr0WYukAAfcQ46fJ7Jje5ZBG8heBd61wxwKfuDDt6MD191PLWHjgy6sgA6zwXikGkQsTeeA==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIGbDCCBVSgAwIBAgIDA+76MA0GCSqGSIb3DQEBCwUAMIGGMQswCQYDVQQGEwJJVDEVMBMGA1UECgwMSU5GT0NFUlQgU1BBMRswGQYDVQQLDBJFbnRlIENlcnRpZmljYXRvcmUxFDASBgNVBAUTCzA3OTQ1MjExMDA2MS0wKwYDVQQDDCRJbmZvQ2VydCBTZXJ2aXppIGRpIENlcnRpZmljYXppb25lIDIwHhcNMTYwMTEyMDkyNDI4WhcNMTkwMTEyMDAwMDAwWjCBsTEUMBIGA1UELhMLMDc5NDUyMTEwMDYxDzANBgkqhkiG9w0BCQEWADEUMBIGA1UEBRMLMDc5NDUyMTEwMDYxHTAbBgNVBAMMFGlkZW50aXR5LmluZm9jZXJ0Lml0MRQwEgYDVQQLDAtJbmZvQ2VydCBJRDEhMB8GA1UECgwYSW5mb0NlcnQgU3BBLzA3OTQ1MjExMDA2MQ0wCwYDVQQHDARSb21hMQswCQYDVQQGEwJJVDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALDysrpnXB+it94LSuAmOgyFDilZ8nuSEVOFl1PX/HtgK3W25B/tqJBsyZwrAIXxg5XHYd3+i7bFoBjuduzfqhvSv9WYCVtggsz5a3sbOpU54DaOLgoCmd4nIsINwKzCmT1UNXBGjS+Xt5F3lV+v2Ayr4rAsPnkE2084BLmwcIX3w7+rx/Nd+/5HfaAMaORICYinUIvbZ5e/plUj87s1YEpep/DcC0uMFE66jFrcnHVOeHCrDh+tAZAiGew4BVJjLr0hfS4ZeaE43TJlHb00GZNfpfzGcOPbzWlSB5iF/cZbTRHmPsn0gALfpPNViniFBVqSaoywZwvkFosrehRUCNkCAwEAAaOCArQwggKwMBMGA1UdJQQMMAoGCCsGAQUFBwMCMCUGA1UdEgQeMByBGmZpcm1hLmRpZ2l0YWxlQGluZm9jZXJ0Lml0MGUGA1UdIAReMFwwWgYGK0wkAQEIMFAwTgYIKwYBBQUHAgIwQgxASW5mb0NlcnQgU3BBIFNTTCwgU01JTUUgYW5kIGRpZ2l0YWwgc2lnbmF0dXJlIENsaWVudCBDZXJ0aWZpY2F0ZTA3BggrBgEFBQcBAQQrMCkwJwYIKwYBBQUHMAGGG2h0dHA6Ly9vY3NwLnNjLmluZm9jZXJ0Lml0LzCB7AYDVR0fBIHkMIHhMDSgMqAwhi5odHRwOi8vY3JsLmluZm9jZXJ0Lml0L2NybHMvc2Vydml6aTIvQ1JMMDEuY3JsMIGooIGloIGihoGfbGRhcDovL2xkYXAuaW5mb2NlcnQuaXQvY24lM0RJbmZvQ2VydCUyMFNlcnZpemklMjBkaSUyMENlcnRpZmljYXppb25lJTIwMiUyMENSTDAxLG91JTNERW50ZSUyMENlcnRpZmljYXRvcmUsbyUzRElORk9DRVJUJTIwU1BBLEMlM0RJVD9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0MA4GA1UdDwEB/wQEAwIEsDCBswYDVR0jBIGrMIGogBTpNppkKVKhWv5ppMSDt4B9D2oSeKGBjKSBiTCBhjELMAkGA1UEBhMCSVQxFTATBgNVBAoMDElORk9DRVJUIFNQQTEbMBkGA1UECwwSRW50ZSBDZXJ0aWZpY2F0b3JlMRQwEgYDVQQFEwswNzk0NTIxMTAwNjEtMCsGA1UEAwwkSW5mb0NlcnQgU2Vydml6aSBkaSBDZXJ0aWZpY2F6aW9uZSAyggECMB0GA1UdDgQWBBTi8mIRU4ue/0lKSfv4gSQhoZQvozANBgkqhkiG9w0BAQsFAAOCAQEAUCXyjmfzxmyVQbK4cf79zj5qMZVAAjDMTR1UGFcS2IibICh3S3Uf22lPGQfm+MX9tiweETW7fBLW6lrR2ofXBz/FfU98A/AA9GZDrbGhBxoc+RoqkHVYRqEuXOq6z3X9DuvsdsfKeO3p4eXbXlCcxD2PP5fFqcZxx1WZ1HRamiGk9fMN1iT3aPa3q7TfRD6W6+XgafjXieZ8bCa1FGIfapbqsWa91jdn4xiJpbmTTq1/Zjs5RCZYzmMEV9rSuSVgFtONb8+xKC4ohMVxAUw2yZHwd4dDyBLkapuaWkzhW939+gjeoKz04Ds2C52d/kln7ehdu9LkzvRI6UAEpAYLgg==</X509Certificate></X509Data></KeyInfo></Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlsso\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlsso\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio fisico\" Name=\"address\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Ragione o denominazione sociale\" Name=\"companyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Provincia di nascita\" Name=\"countyOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di nascita\" Name=\"dateOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio digitale\" Name=\"digitalAddress\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Indirizzo di posta elettronica\" Name=\"email\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di scadenza identita\" Name=\"expirationDate\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Cognome\" Name=\"familyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice fiscale\" Name=\"fiscalNumber\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sesso\" Name=\"gender\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Documento d''identita\" Name=\"idCard\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Partita IVA\" Name=\"ivaCode\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Numero di telefono mobile\" Name=\"mobilePhone\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Nome\" Name=\"name\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Luogo di nascita\" Name=\"placeOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sede legale\" Name=\"registeredOffice\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice identificativo SPID\" Name=\"spidCode\"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"it\">https://www.infocert.it</md:OrganizationURL><md:OrganizationURL xml:lang=\"en\">https://www.infocert.it/international/?lang=en</md:OrganizationURL><md:OrganizationURL xml:lang=\"fr\">https://www.infocert.it/international/?lang=fr</md:OrganizationURL><md:OrganizationURL xml:lang=\"de\">https://www.infocert.it/international/?lang=de</md:OrganizationURL></md:Organization></md:EntityDescriptor>\r\r",
        "x509cert": "-----BEGIN CERTIFICATE-----\n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\n-----END CERTIFICATE-----",
    "provider": ""
  },
  "apiVersion": "1.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (65, 'b021df92-4f2c-4fc3-a0e8-87077ca8e1e4', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 17:22:00.305398+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\" standalone=\"no\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"_25b183c4c721960977003fb04ec600b5\" cacheDuration=\"P0Y0M30DT0H0M0.000S\" entityID=\"https://identity.infocert.it\"><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"#_25b183c4c721960977003fb04ec600b4\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>hKbiiLWanDYNT69FQLh4uWlI6rVdAfoNXltq8WE83No=</DigestValue></Reference></SignedInfo><SignatureValue>nqWCyBqw40iHn3OEF9qVnJIzX9xmTzoq3EE9pbpPtrrAnjBWKTI2GxCAH84oD7BArJ/oBWOEQ0iJzFLwdtJK56ly8MwFAiYdCuNm9wHd03gSGBMxaWbhQSfwkwRCmMbzxcXJGMhh4JECOdZ87KR861A+S2EPyWBHC9yx8iRZ4UtmrGpf3UWyFJsCEjCLZv+a/ld6WnkP43OqJhs84BQWrH+Z1QOy1GDDYe+sItvQ1BhOomDT6x+ZsrMntgAItF+1kQxJ5CPRzGkYb10vr0WYukAAfcQ46fJ7Jje5ZBG8heBd61wxwKfuDDt6MD191PLWHjgy6sgA6zwXikGkQsTeeA==</SignatureValue><KeyInfo><X509Data><X509Certificate>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</X509Certificate></X509Data></KeyInfo></Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlsso\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlsso\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio fisico\" Name=\"address\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Ragione o denominazione sociale\" Name=\"companyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Provincia di nascita\" Name=\"countyOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di nascita\" Name=\"dateOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio digitale\" Name=\"digitalAddress\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Indirizzo di posta elettronica\" Name=\"email\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di scadenza identita\" Name=\"expirationDate\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Cognome\" Name=\"familyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice fiscale\" Name=\"fiscalNumber\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sesso\" Name=\"gender\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Documento d''identita\" Name=\"idCard\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Partita IVA\" Name=\"ivaCode\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Numero di telefono mobile\" Name=\"mobilePhone\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Nome\" Name=\"name\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Luogo di nascita\" Name=\"placeOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sede legale\" Name=\"registeredOffice\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice identificativo SPID\" Name=\"spidCode\"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"it\">https://www.infocert.it</md:OrganizationURL><md:OrganizationURL xml:lang=\"en\">https://www.infocert.it/international/?lang=en</md:OrganizationURL><md:OrganizationURL xml:lang=\"fr\">https://www.infocert.it/international/?lang=fr</md:OrganizationURL><md:OrganizationURL xml:lang=\"de\">https://www.infocert.it/international/?lang=de</md:OrganizationURL></md:Organization></md:EntityDescriptor>\r\r",
        "x509cert": "-----BEGIN CERTIFICATE-----\nMIIGbDCCBVSgAwIBAgIDA+76MA0GCSqGSIb3DQEBCwUAMIGGMQswCQYDVQQGEwJJVDEVMBMGA1UECgwMSU5GT0NFUlQgU1BBMRswGQYDVQQLDBJFbnRlIENlcnRpZmljYXRvcmUxFDASBgNVBAUTCzA3OTQ1MjExMDA2MS0wKwYDVQQDDCRJbmZvQ2VydCBTZXJ2aXppIGRpIENlcnRpZmljYXppb25lIDIwHhcNMTYwMTEyMDkyNDI4WhcNMTkwMTEyMDAwMDAwWjCBsTEUMBIGA1UELhMLMDc5NDUyMTEwMDYxDzANBgkqhkiG9w0BCQEWADEUMBIGA1UEBRMLMDc5NDUyMTEwMDYxHTAbBgNVBAMMFGlkZW50aXR5LmluZm9jZXJ0Lml0MRQwEgYDVQQLDAtJbmZvQ2VydCBJRDEhMB8GA1UECgwYSW5mb0NlcnQgU3BBLzA3OTQ1MjExMDA2MQ0wCwYDVQQHDARSb21hMQswCQYDVQQGEwJJVDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALDysrpnXB+it94LSuAmOgyFDilZ8nuSEVOFl1PX/HtgK3W25B/tqJBsyZwrAIXxg5XHYd3+i7bFoBjuduzfqhvSv9WYCVtggsz5a3sbOpU54DaOLgoCmd4nIsINwKzCmT1UNXBGjS+Xt5F3lV+v2Ayr4rAsPnkE2084BLmwcIX3w7+rx/Nd+/5HfaAMaORICYinUIvbZ5e/plUj87s1YEpep/DcC0uMFE66jFrcnHVOeHCrDh+tAZAiGew4BVJjLr0hfS4ZeaE43TJlHb00GZNfpfzGcOPbzWlSB5iF/cZbTRHmPsn0gALfpPNViniFBVqSaoywZwvkFosrehRUCNkCAwEAAaOCArQwggKwMBMGA1UdJQQMMAoGCCsGAQUFBwMCMCUGA1UdEgQeMByBGmZpcm1hLmRpZ2l0YWxlQGluZm9jZXJ0Lml0MGUGA1UdIAReMFwwWgYGK0wkAQEIMFAwTgYIKwYBBQUHAgIwQgxASW5mb0NlcnQgU3BBIFNTTCwgU01JTUUgYW5kIGRpZ2l0YWwgc2lnbmF0dXJlIENsaWVudCBDZXJ0aWZpY2F0ZTA3BggrBgEFBQcBAQQrMCkwJwYIKwYBBQUHMAGGG2h0dHA6Ly9vY3NwLnNjLmluZm9jZXJ0Lml0LzCB7AYDVR0fBIHkMIHhMDSgMqAwhi5odHRwOi8vY3JsLmluZm9jZXJ0Lml0L2NybHMvc2Vydml6aTIvQ1JMMDEuY3JsMIGooIGloIGihoGfbGRhcDovL2xkYXAuaW5mb2NlcnQuaXQvY24lM0RJbmZvQ2VydCUyMFNlcnZpemklMjBkaSUyMENlcnRpZmljYXppb25lJTIwMiUyMENSTDAxLG91JTNERW50ZSUyMENlcnRpZmljYXRvcmUsbyUzRElORk9DRVJUJTIwU1BBLEMlM0RJVD9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0MA4GA1UdDwEB/wQEAwIEsDCBswYDVR0jBIGrMIGogBTpNppkKVKhWv5ppMSDt4B9D2oSeKGBjKSBiTCBhjELMAkGA1UEBhMCSVQxFTATBgNVBAoMDElORk9DRVJUIFNQQTEbMBkGA1UECwwSRW50ZSBDZXJ0aWZpY2F0b3JlMRQwEgYDVQQFEwswNzk0NTIxMTAwNjEtMCsGA1UEAwwkSW5mb0NlcnQgU2Vydml6aSBkaSBDZXJ0aWZpY2F6aW9uZSAyggECMB0GA1UdDgQWBBTi8mIRU4ue/0lKSfv4gSQhoZQvozANBgkqhkiG9w0BAQsFAAOCAQEAUCXyjmfzxmyVQbK4cf79zj5qMZVAAjDMTR1UGFcS2IibICh3S3Uf22lPGQfm+MX9tiweETW7fBLW6lrR2ofXBz/FfU98A/AA9GZDrbGhBxoc+RoqkHVYRqEuXOq6z3X9DuvsdsfKeO3p4eXbXlCcxD2PP5fFqcZxx1WZ1HRamiGk9fMN1iT3aPa3q7TfRD6W6+XgafjXieZ8bCa1FGIfapbqsWa91jdn4xiJpbmTTq1/Zjs5RCZYzmMEV9rSuSVgFtONb8+xKC4ohMVxAUw2yZHwd4dDyBLkapuaWkzhW939+gjeoKz04Ds2C52d/kln7ehdu9LkzvRI6UAEpAYLgg==\n-----END CERTIFICATE-----",
    "provider": ""
  },
  "apiVersion": "1.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (66, '40233e02-43be-44cb-83c2-9323a8ea96c8', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 17:22:10.75113+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\" standalone=\"no\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"_25b183c4c721960977003fb04ec600b4\" cacheDuration=\"P0Y0M30DT0H0M0.000S\" entityID=\"https://identity.infocert.it\"><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"#_25b183c4c721960977003fb04ec600b4\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>hKbiiLWanDYNT69FQLh4uWlI6rVdAfoNXltq8WE83No=</DigestValue></Reference></SignedInfo><SignatureValue>nqWCyBqw40iHn3OEF9qVnJIzX9xmTzoq3EE9pbpPtrrAnjBWKTI2GxCAH84oD7BArJ/oBWOEQ0iJzFLwdtJK56ly8MwFAiYdCuNm9wHd03gSGBMxaWbhQSfwkwRCmMbzxcXJGMhh4JECOdZ87KR861A+S2EPyWBHC9yx8iRZ4UtmrGpf3UWyFJsCEjCLZv+a/ld6WnkP43OqJhs84BQWrH+Z1QOy1GDDYe+sItvQ1BhOomDT6x+ZsrMntgAItF+1kQxJ5CPRzGkYb10vr0WYukAAfcQ46fJ7Jje5ZBG8heBd61wxwKfuDDt6MD191PLWHjgy6sgA6zwXikGkQsTeeA==</SignatureValue><KeyInfo><X509Data><X509Certificate>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</X509Certificate></X509Data></KeyInfo></Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlsso\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlsso\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio fisico\" Name=\"address\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Ragione o denominazione sociale\" Name=\"companyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Provincia di nascita\" Name=\"countyOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di nascita\" Name=\"dateOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio digitale\" Name=\"digitalAddress\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Indirizzo di posta elettronica\" Name=\"email\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di scadenza identita\" Name=\"expirationDate\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Cognome\" Name=\"familyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice fiscale\" Name=\"fiscalNumber\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sesso\" Name=\"gender\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Documento d''identita\" Name=\"idCard\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Partita IVA\" Name=\"ivaCode\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Numero di telefono mobile\" Name=\"mobilePhone\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Nome\" Name=\"name\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Luogo di nascita\" Name=\"placeOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sede legale\" Name=\"registeredOffice\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice identificativo SPID\" Name=\"spidCode\"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"it\">https://www.infocert.it</md:OrganizationURL><md:OrganizationURL xml:lang=\"en\">https://www.infocert.it/international/?lang=en</md:OrganizationURL><md:OrganizationURL xml:lang=\"fr\">https://www.infocert.it/international/?lang=fr</md:OrganizationURL><md:OrganizationURL xml:lang=\"de\">https://www.infocert.it/international/?lang=de</md:OrganizationURL></md:Organization></md:EntityDescriptor>\r\r",
        "x509cert": "-----BEGIN CERTIFICATE-----\n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\n-----END CERTIFICATE-----",
    "provider": ""
  },
  "apiVersion": "1.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (67, '2329b01f-6ae4-4248-919b-0141f0259b8f', 'GET', 'http://192.168.56.103:8888/api/prvd/infocrt/metadata', '2017-07-25 10:42:46.769137+02', '192.168.56.1', NULL);
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (68, '6031a700-c89c-4fdf-8d33-8344881e8484', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-25 10:46:23.191562+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\" standalone=\"no\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"_25b183c4c721960977003fb04ec600b4\" cacheDuration=\"P0Y0M30DT0H0M0.000S\" entityID=\"https://identity.infocert.it\"><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"#_25b183c4c721960977003fb04ec600b4\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>hKbiiLWanDYNT69FQLh4uWlI6rVdAfoNXltq8WE83No=</DigestValue></Reference></SignedInfo><SignatureValue>nqWCyBqw40iHn3OEF9qVnJIzX9xmTzoq3EE9pbpPtrrAnjBWKTI2GxCAH84oD7BArJ/oBWOEQ0iJzFLwdtJK56ly8MwFAiYdCuNm9wHd03gSGBMxaWbhQSfwkwRCmMbzxcXJGMhh4JECOdZ87KR861A+S2EPyWBHC9yx8iRZ4UtmrGpf3UWyFJsCEjCLZv+a/ld6WnkP43OqJhs84BQWrH+Z1QOy1GDDYe+sItvQ1BhOomDT6x+ZsrMntgAItF+1kQxJ5CPRzGkYb10vr0WYukAAfcQ46fJ7Jje5ZBG8heBd61wxwKfuDDt6MD191PLWHjgy6sgA6zwXikGkQsTeeA==</SignatureValue><KeyInfo><X509Data><X509Certificate>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</X509Certificate></X509Data></KeyInfo></Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlsso\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlsso\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio fisico\" Name=\"address\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Ragione o denominazione sociale\" Name=\"companyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Provincia di nascita\" Name=\"countyOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di nascita\" Name=\"dateOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio digitale\" Name=\"digitalAddress\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Indirizzo di posta elettronica\" Name=\"email\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di scadenza identita\" Name=\"expirationDate\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Cognome\" Name=\"familyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice fiscale\" Name=\"fiscalNumber\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sesso\" Name=\"gender\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Documento d''identita\" Name=\"idCard\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Partita IVA\" Name=\"ivaCode\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Numero di telefono mobile\" Name=\"mobilePhone\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Nome\" Name=\"name\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Luogo di nascita\" Name=\"placeOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sede legale\" Name=\"registeredOffice\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice identificativo SPID\" Name=\"spidCode\"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"it\">https://www.infocert.it</md:OrganizationURL><md:OrganizationURL xml:lang=\"en\">https://www.infocert.it/international/?lang=en</md:OrganizationURL><md:OrganizationURL xml:lang=\"fr\">https://www.infocert.it/international/?lang=fr</md:OrganizationURL><md:OrganizationURL xml:lang=\"de\">https://www.infocert.it/international/?lang=de</md:OrganizationURL></md:Organization></md:EntityDescriptor>\r\r",
    "provider": ""
  },
  "apiVersion": "1.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (69, 'e7ac878a-cfb7-4198-88ab-6d9512b1d785', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-25 10:47:50.820628+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\" standalone=\"no\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"_25b183c4c721960977003fb04ec600b4\" cacheDuration=\"P0Y0M30DT0H0M0.000S\" entityID=\"https://identity.infocert.it\"><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"#_25b183c4c721960977003fb04ec600b4\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>hKbiiLWanDYNT69FQLh4uWlI6rVdAfoNXltq8WE83No=</DigestValue></Reference></SignedInfo><SignatureValue>nqWCyBqw40iHn3OEF9qVnJIzX9xmTzoq3EE9pbpPtrrAnjBWKTI2GxCAH84oD7BArJ/oBWOEQ0iJzFLwdtJK56ly8MwFAiYdCuNm9wHd03gSGBMxaWbhQSfwkwRCmMbzxcXJGMhh4JECOdZ87KR861A+S2EPyWBHC9yx8iRZ4UtmrGpf3UWyFJsCEjCLZv+a/ld6WnkP43OqJhs84BQWrH+Z1QOy1GDDYe+sItvQ1BhOomDT6x+ZsrMntgAItF+1kQxJ5CPRzGkYb10vr0WYukAAfcQ46fJ7Jje5ZBG8heBd61wxwKfuDDt6MD191PLWHjgy6sgA6zwXikGkQsTeeA==</SignatureValue><KeyInfo><X509Data><X509Certificate>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</X509Certificate></X509Data></KeyInfo></Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlsso\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlsso\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio fisico\" Name=\"address\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Ragione o denominazione sociale\" Name=\"companyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Provincia di nascita\" Name=\"countyOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di nascita\" Name=\"dateOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio digitale\" Name=\"digitalAddress\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Indirizzo di posta elettronica\" Name=\"email\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di scadenza identita\" Name=\"expirationDate\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Cognome\" Name=\"familyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice fiscale\" Name=\"fiscalNumber\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sesso\" Name=\"gender\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Documento d''identita\" Name=\"idCard\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Partita IVA\" Name=\"ivaCode\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Numero di telefono mobile\" Name=\"mobilePhone\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Nome\" Name=\"name\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Luogo di nascita\" Name=\"placeOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sede legale\" Name=\"registeredOffice\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice identificativo SPID\" Name=\"spidCode\"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"it\">https://www.infocert.it</md:OrganizationURL><md:OrganizationURL xml:lang=\"en\">https://www.infocert.it/international/?lang=en</md:OrganizationURL><md:OrganizationURL xml:lang=\"fr\">https://www.infocert.it/international/?lang=fr</md:OrganizationURL><md:OrganizationURL xml:lang=\"de\">https://www.infocert.it/international/?lang=de</md:OrganizationURL></md:Organization></md:EntityDescriptor>\r\r",
    "provider": ""
  },
  "apiVersion": "1.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (70, 'e756a4a9-a5af-4d7d-ac0b-96eac2c6d535', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-25 10:48:41.829675+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\" standalone=\"no\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"_25b183c4c721960977003fb04ec600b4\" cacheDuration=\"P0Y0M30DT0H0M0.000S\" entityID=\"https://identity.infocert.it\"><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"#_25b183c4c721960977003fb04ec600b4\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>hKbiiLWanDYNT69FQLh4uWlI6rVdAfoNXltq8WE83No=</DigestValue></Reference></SignedInfo><SignatureValue>nqWCyBqw40iHn3OEF9qVnJIzX9xmTzoq3EE9pbpPtrrAnjBWKTI2GxCAH84oD7BArJ/oBWOEQ0iJzFLwdtJK56ly8MwFAiYdCuNm9wHd03gSGBMxaWbhQSfwkwRCmMbzxcXJGMhh4JECOdZ87KR861A+S2EPyWBHC9yx8iRZ4UtmrGpf3UWyFJsCEjCLZv+a/ld6WnkP43OqJhs84BQWrH+Z1QOy1GDDYe+sItvQ1BhOomDT6x+ZsrMntgAItF+1kQxJ5CPRzGkYb10vr0WYukAAfcQ46fJ7Jje5ZBG8heBd61wxwKfuDDt6MD191PLWHjgy6sgA6zwXikGkQsTeeA==</SignatureValue><KeyInfo><X509Data><X509Certificate>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</X509Certificate></X509Data></KeyInfo></Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlsso\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlsso\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio fisico\" Name=\"address\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Ragione o denominazione sociale\" Name=\"companyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Provincia di nascita\" Name=\"countyOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di nascita\" Name=\"dateOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio digitale\" Name=\"digitalAddress\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Indirizzo di posta elettronica\" Name=\"email\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di scadenza identita\" Name=\"expirationDate\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Cognome\" Name=\"familyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice fiscale\" Name=\"fiscalNumber\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sesso\" Name=\"gender\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Documento d''identita\" Name=\"idCard\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Partita IVA\" Name=\"ivaCode\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Numero di telefono mobile\" Name=\"mobilePhone\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Nome\" Name=\"name\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Luogo di nascita\" Name=\"placeOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sede legale\" Name=\"registeredOffice\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice identificativo SPID\" Name=\"spidCode\"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"it\">https://www.infocert.it</md:OrganizationURL><md:OrganizationURL xml:lang=\"en\">https://www.infocert.it/international/?lang=en</md:OrganizationURL><md:OrganizationURL xml:lang=\"fr\">https://www.infocert.it/international/?lang=fr</md:OrganizationURL><md:OrganizationURL xml:lang=\"de\">https://www.infocert.it/international/?lang=de</md:OrganizationURL></md:Organization></md:EntityDescriptor>\r\r",
    "provider": ""
  },
  "apiVersion": "1.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (71, '65e12a76-9c11-4619-9364-aaaf5d038b63', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-25 11:01:14.358988+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\" standalone=\"no\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"_25b183c4c721960977003fb04ec600b4\" cacheDuration=\"P0Y0M30DT0H0M0.000S\" entityID=\"https://identity.infocert.it\"><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"#_25b183c4c721960977003fb04ec600b4\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>hKbiiLWanDYNT69FQLh4uWlI6rVdAfoNXltq8WE83No=</DigestValue></Reference></SignedInfo><SignatureValue>nqWCyBqw40iHn3OEF9qVnJIzX9xmTzoq3EE9pbpPtrrAnjBWKTI2GxCAH84oD7BArJ/oBWOEQ0iJzFLwdtJK56ly8MwFAiYdCuNm9wHd03gSGBMxaWbhQSfwkwRCmMbzxcXJGMhh4JECOdZ87KR861A+S2EPyWBHC9yx8iRZ4UtmrGpf3UWyFJsCEjCLZv+a/ld6WnkP43OqJhs84BQWrH+Z1QOy1GDDYe+sItvQ1BhOomDT6x+ZsrMntgAItF+1kQxJ5CPRzGkYb10vr0WYukAAfcQ46fJ7Jje5ZBG8heBd61wxwKfuDDt6MD191PLWHjgy6sgA6zwXikGkQsTeeA==</SignatureValue><KeyInfo><X509Data><X509Certificate>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</X509Certificate></X509Data></KeyInfo></Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlsso\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlsso\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio fisico\" Name=\"address\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Ragione o denominazione sociale\" Name=\"companyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Provincia di nascita\" Name=\"countyOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di nascita\" Name=\"dateOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio digitale\" Name=\"digitalAddress\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Indirizzo di posta elettronica\" Name=\"email\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di scadenza identita\" Name=\"expirationDate\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Cognome\" Name=\"familyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice fiscale\" Name=\"fiscalNumber\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sesso\" Name=\"gender\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Documento d''identita\" Name=\"idCard\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Partita IVA\" Name=\"ivaCode\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Numero di telefono mobile\" Name=\"mobilePhone\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Nome\" Name=\"name\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Luogo di nascita\" Name=\"placeOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sede legale\" Name=\"registeredOffice\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice identificativo SPID\" Name=\"spidCode\"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"it\">https://www.infocert.it</md:OrganizationURL><md:OrganizationURL xml:lang=\"en\">https://www.infocert.it/international/?lang=en</md:OrganizationURL><md:OrganizationURL xml:lang=\"fr\">https://www.infocert.it/international/?lang=fr</md:OrganizationURL><md:OrganizationURL xml:lang=\"de\">https://www.infocert.it/international/?lang=de</md:OrganizationURL></md:Organization></md:EntityDescriptor>\r\r",
    "provider": ""
  },
  "apiVersion": "1.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (72, '10589102-802b-4495-a482-3e79794d80ac', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-25 11:06:54.383927+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\" standalone=\"no\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"_25b183c4c721960977003fb04ec600b4\" cacheDuration=\"P0Y0M30DT0H0M0.000S\" entityID=\"https://identity.infocert.it\"><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"#_25b183c4c721960977003fb04ec600b4\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>hKbiiLWanDYNT69FQLh4uWlI6rVdAfoNXltq8WE83No=</DigestValue></Reference></SignedInfo><SignatureValue>nqWCyBqw40iHn3OEF9qVnJIzX9xmTzoq3EE9pbpPtrrAnjBWKTI2GxCAH84oD7BArJ/oBWOEQ0iJzFLwdtJK56ly8MwFAiYdCuNm9wHd03gSGBMxaWbhQSfwkwRCmMbzxcXJGMhh4JECOdZ87KR861A+S2EPyWBHC9yx8iRZ4UtmrGpf3UWyFJsCEjCLZv+a/ld6WnkP43OqJhs84BQWrH+Z1QOy1GDDYe+sItvQ1BhOomDT6x+ZsrMntgAItF+1kQxJ5CPRzGkYb10vr0WYukAAfcQ46fJ7Jje5ZBG8heBd61wxwKfuDDt6MD191PLWHjgy6sgA6zwXikGkQsTeeA==</SignatureValue><KeyInfo><X509Data><X509Certificate>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</X509Certificate></X509Data></KeyInfo></Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlsso\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlsso\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio fisico\" Name=\"address\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Ragione o denominazione sociale\" Name=\"companyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Provincia di nascita\" Name=\"countyOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di nascita\" Name=\"dateOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio digitale\" Name=\"digitalAddress\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Indirizzo di posta elettronica\" Name=\"email\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di scadenza identita\" Name=\"expirationDate\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Cognome\" Name=\"familyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice fiscale\" Name=\"fiscalNumber\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sesso\" Name=\"gender\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Documento d''identita\" Name=\"idCard\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Partita IVA\" Name=\"ivaCode\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Numero di telefono mobile\" Name=\"mobilePhone\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Nome\" Name=\"name\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Luogo di nascita\" Name=\"placeOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sede legale\" Name=\"registeredOffice\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice identificativo SPID\" Name=\"spidCode\"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"it\">https://www.infocert.it</md:OrganizationURL><md:OrganizationURL xml:lang=\"en\">https://www.infocert.it/international/?lang=en</md:OrganizationURL><md:OrganizationURL xml:lang=\"fr\">https://www.infocert.it/international/?lang=fr</md:OrganizationURL><md:OrganizationURL xml:lang=\"de\">https://www.infocert.it/international/?lang=de</md:OrganizationURL></md:Organization></md:EntityDescriptor>\r\r",
    "provider": ""
  },
  "apiVersion": "1.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (73, '65363a86-d47b-4377-ab2d-e2b171672dfb', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-25 11:08:58.806976+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\" standalone=\"no\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"_25b183c4c721960977003fb04ec600b4\" cacheDuration=\"P0Y0M30DT0H0M0.000S\" entityID=\"https://identity.infocert.it\"><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"#_25b183c4c721960977003fb04ec600b4\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>hKbiiLWanDYNT69FQLh4uWlI6rVdAfoNXltq8WE83No=</DigestValue></Reference></SignedInfo><SignatureValue>nqWCyBqw40iHn3OEF9qVnJIzX9xmTzoq3EE9pbpPtrrAnjBWKTI2GxCAH84oD7BArJ/oBWOEQ0iJzFLwdtJK56ly8MwFAiYdCuNm9wHd03gSGBMxaWbhQSfwkwRCmMbzxcXJGMhh4JECOdZ87KR861A+S2EPyWBHC9yx8iRZ4UtmrGpf3UWyFJsCEjCLZv+a/ld6WnkP43OqJhs84BQWrH+Z1QOy1GDDYe+sItvQ1BhOomDT6x+ZsrMntgAItF+1kQxJ5CPRzGkYb10vr0WYukAAfcQ46fJ7Jje5ZBG8heBd61wxwKfuDDt6MD191PLWHjgy6sgA6zwXikGkQsTeeA==</SignatureValue><KeyInfo><X509Data><X509Certificate>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</X509Certificate></X509Data></KeyInfo></Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlsso\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlsso\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio fisico\" Name=\"address\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Ragione o denominazione sociale\" Name=\"companyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Provincia di nascita\" Name=\"countyOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di nascita\" Name=\"dateOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio digitale\" Name=\"digitalAddress\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Indirizzo di posta elettronica\" Name=\"email\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di scadenza identita\" Name=\"expirationDate\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Cognome\" Name=\"familyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice fiscale\" Name=\"fiscalNumber\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sesso\" Name=\"gender\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Documento d''identita\" Name=\"idCard\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Partita IVA\" Name=\"ivaCode\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Numero di telefono mobile\" Name=\"mobilePhone\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Nome\" Name=\"name\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Luogo di nascita\" Name=\"placeOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sede legale\" Name=\"registeredOffice\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice identificativo SPID\" Name=\"spidCode\"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"it\">https://www.infocert.it</md:OrganizationURL><md:OrganizationURL xml:lang=\"en\">https://www.infocert.it/international/?lang=en</md:OrganizationURL><md:OrganizationURL xml:lang=\"fr\">https://www.infocert.it/international/?lang=fr</md:OrganizationURL><md:OrganizationURL xml:lang=\"de\">https://www.infocert.it/international/?lang=de</md:OrganizationURL></md:Organization></md:EntityDescriptor>\r\r",
    "provider": ""
  },
  "apiVersion": "1.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (74, 'f917170b-2fdd-4cfb-a695-c198a7f09522', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-25 11:10:10.731668+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\" standalone=\"no\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"_25b183c4c721960977003fb04ec600b4\" cacheDuration=\"P0Y0M30DT0H0M0.000S\" entityID=\"https://identity.infocert.it\"><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"#_25b183c4c721960977003fb04ec600b4\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>hKbiiLWanDYNT69FQLh4uWlI6rVdAfoNXltq8WE83No=</DigestValue></Reference></SignedInfo><SignatureValue>nqWCyBqw40iHn3OEF9qVnJIzX9xmTzoq3EE9pbpPtrrAnjBWKTI2GxCAH84oD7BArJ/oBWOEQ0iJzFLwdtJK56ly8MwFAiYdCuNm9wHd03gSGBMxaWbhQSfwkwRCmMbzxcXJGMhh4JECOdZ87KR861A+S2EPyWBHC9yx8iRZ4UtmrGpf3UWyFJsCEjCLZv+a/ld6WnkP43OqJhs84BQWrH+Z1QOy1GDDYe+sItvQ1BhOomDT6x+ZsrMntgAItF+1kQxJ5CPRzGkYb10vr0WYukAAfcQ46fJ7Jje5ZBG8heBd61wxwKfuDDt6MD191PLWHjgy6sgA6zwXikGkQsTeeA==</SignatureValue><KeyInfo><X509Data><X509Certificate>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</X509Certificate></X509Data></KeyInfo></Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIIGbDCCBVSgAwIBAgIDA+76MA0GCSqGSIb3DQEBCwUAMIGGMQswCQYDVQQGEwJJVDEVMBMGA1UECgwMSU5GT0NFUlQgU1BBMRswGQYDVQQLDBJFbnRlIENlcnRpZmljYXRvcmUxFDASBgNVBAUTCzA3OTQ1MjExMDA2MS0wKwYDVQQDDCRJbmZvQ2VydCBTZXJ2aXppIGRpIENlcnRpZmljYXppb25lIDIwHhcNMTYwMTEyMDkyNDI4WhcNMTkwMTEyMDAwMDAwWjCBsTEUMBIGA1UELhMLMDc5NDUyMTEwMDYxDzANBgkqhkiG9w0BCQEWADEUMBIGA1UEBRMLMDc5NDUyMTEwMDYxHTAbBgNVBAMMFGlkZW50aXR5LmluZm9jZXJ0Lml0MRQwEgYDVQQLDAtJbmZvQ2VydCBJRDEhMB8GA1UECgwYSW5mb0NlcnQgU3BBLzA3OTQ1MjExMDA2MQ0wCwYDVQQHDARSb21hMQswCQYDVQQGEwJJVDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALDysrpnXB+it94LSuAmOgyFDilZ8nuSEVOFl1PX/HtgK3W25B/tqJBsyZwrAIXxg5XHYd3+i7bFoBjuduzfqhvSv9WYCVtggsz5a3sbOpU54DaOLgoCmd4nIsINwKzCmT1UNXBGjS+Xt5F3lV+v2Ayr4rAsPnkE2084BLmwcIX3w7+rx/Nd+/5HfaAMaORICYinUIvbZ5e/plUj87s1YEpep/DcC0uMFE66jFrcnHVOeHCrDh+tAZAiGew4BVJjLr0hfS4ZeaE43TJlHb00GZNfpfzGcOPbzWlSB5iF/cZbTRHmPsn0gALfpPNViniFBVqSaoywZwvkFosrehRUCNkCAwEAAaOCArQwggKwMBMGA1UdJQQMMAoGCCsGAQUFBwMCMCUGA1UdEgQeMByBGmZpcm1hLmRpZ2l0YWxlQGluZm9jZXJ0Lml0MGUGA1UdIAReMFwwWgYGK0wkAQEIMFAwTgYIKwYBBQUHAgIwQgxASW5mb0NlcnQgU3BBIFNTTCwgU01JTUUgYW5kIGRpZ2l0YWwgc2lnbmF0dXJlIENsaWVudCBDZXJ0aWZpY2F0ZTA3BggrBgEFBQcBAQQrMCkwJwYIKwYBBQUHMAGGG2h0dHA6Ly9vY3NwLnNjLmluZm9jZXJ0Lml0LzCB7AYDVR0fBIHkMIHhMDSgMqAwhi5odHRwOi8vY3JsLmluZm9jZXJ0Lml0L2NybHMvc2Vydml6aTIvQ1JMMDEuY3JsMIGooIGloIGihoGfbGRhcDovL2xkYXAuaW5mb2NlcnQuaXQvY24lM0RJbmZvQ2VydCUyMFNlcnZpemklMjBkaSUyMENlcnRpZmljYXppb25lJTIwMiUyMENSTDAxLG91JTNERW50ZSUyMENlcnRpZmljYXRvcmUsbyUzRElORk9DRVJUJTIwU1BBLEMlM0RJVD9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0MA4GA1UdDwEB/wQEAwIEsDCBswYDVR0jBIGrMIGogBTpNppkKVKhWv5ppMSDt4B9D2oSeKGBjKSBiTCBhjELMAkGA1UEBhMCSVQxFTATBgNVBAoMDElORk9DRVJUIFNQQTEbMBkGA1UECwwSRW50ZSBDZXJ0aWZpY2F0b3JlMRQwEgYDVQQFEwswNzk0NTIxMTAwNjEtMCsGA1UEAwwkSW5mb0NlcnQgU2Vydml6aSBkaSBDZXJ0aWZpY2F6aW9uZSAyggECMB0GA1UdDgQWBBTi8mIRU4ue/0lKSfv4gSQhoZQvozANBgkqhkiG9w0BAQsFAAOCAQEAUCXyjmfzxmyVQbK4cf79zj5qMZVAAjDMTR1UGFcS2IibICh3S3Uf22lPGQfm+MX9tiweETW7fBLW6lrR2ofXBz/FfU98A/AA9GZDrbGhBxoc+RoqkHVYRqEuXOq6z3X9DuvsdsfKeO3p4eXbXlCcxD2PP5fFqcZxx1WZ1HRamiGk9fMN1iT3aPa3q7TfRD6W6+XgafjXieZ8bCa1FGIfapbqsWa91jdn4xiJpbmTTq1/Zjs5RCZYzmMEV9rSuSVgFtONb8+xKC4ohMVxAUw2yZHwd4dDyBLkapuaWkzhW939+gjeoKz04Ds2C52d/kln7ehdu9LkzvRI6UAEpAYLgg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlsso\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlsso\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio fisico\" Name=\"address\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Ragione o denominazione sociale\" Name=\"companyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Provincia di nascita\" Name=\"countyOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di nascita\" Name=\"dateOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio digitale\" Name=\"digitalAddress\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Indirizzo di posta elettronica\" Name=\"email\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di scadenza identita\" Name=\"expirationDate\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Cognome\" Name=\"familyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice fiscale\" Name=\"fiscalNumber\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sesso\" Name=\"gender\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Documento d''identita\" Name=\"idCard\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Partita IVA\" Name=\"ivaCode\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Numero di telefono mobile\" Name=\"mobilePhone\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Nome\" Name=\"name\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Luogo di nascita\" Name=\"placeOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sede legale\" Name=\"registeredOffice\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice identificativo SPID\" Name=\"spidCode\"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"it\">https://www.infocert.it</md:OrganizationURL><md:OrganizationURL xml:lang=\"en\">https://www.infocert.it/international/?lang=en</md:OrganizationURL><md:OrganizationURL xml:lang=\"fr\">https://www.infocert.it/international/?lang=fr</md:OrganizationURL><md:OrganizationURL xml:lang=\"de\">https://www.infocert.it/international/?lang=de</md:OrganizationURL></md:Organization></md:EntityDescriptor>\r\r",
    "provider": ""
  },
  "apiVersion": "1.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (75, 'ac099329-fadc-45e4-9a80-ea35841e214d', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-25 11:12:54.544116+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\" standalone=\"no\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"_25b183c4c721960977003fb04ec600b4\" cacheDuration=\"P0Y0M30DT0H0M0.000S\" entityID=\"https://identity.infocert.it\"><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"#_25b183c4c721960977003fb04ec600b4\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>hKbiiLWanDYNT69FQLh4uWlI6rVdAfoNXltq8WE83No=</DigestValue></Reference></SignedInfo><SignatureValue>nqWCyBqw40iHn3OEF9qVnJIzX9xmTzoq3EE9pbpPtrrAnjBWKTI2GxCAH84oD7BArJ/oBWOEQ0iJzFLwdtJK56ly8MwFAiYdCuNm9wHd03gSGBMxaWbhQSfwkwRCmMbzxcXJGMhh4JECOdZ87KR861A+S2EPyWBHC9yx8iRZ4UtmrGpf3UWyFJsCEjCLZv+a/ld6WnkP43OqJhs84BQWrH+Z1QOy1GDDYe+sItvQ1BhOomDT6x+ZsrMntgAItF+1kQxJ5CPRzGkYb10vr0WYukAAfcQ46fJ7Jje5ZBG8heBd61wxwKfuDDt6MD191PLWHjgy6sgA6zwXikGkQsTeeA==</SignatureValue><KeyInfo><X509Data><X509Certificate>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</X509Certificate></X509Data></KeyInfo></Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlsso\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlsso\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio fisico\" Name=\"address\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Ragione o denominazione sociale\" Name=\"companyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Provincia di nascita\" Name=\"countyOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di nascita\" Name=\"dateOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio digitale\" Name=\"digitalAddress\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Indirizzo di posta elettronica\" Name=\"email\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di scadenza identita\" Name=\"expirationDate\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Cognome\" Name=\"familyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice fiscale\" Name=\"fiscalNumber\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sesso\" Name=\"gender\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Documento d''identita\" Name=\"idCard\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Partita IVA\" Name=\"ivaCode\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Numero di telefono mobile\" Name=\"mobilePhone\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Nome\" Name=\"name\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Luogo di nascita\" Name=\"placeOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sede legale\" Name=\"registeredOffice\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice identificativo SPID\" Name=\"spidCode\"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"it\">https://www.infocert.it</md:OrganizationURL><md:OrganizationURL xml:lang=\"en\">https://www.infocert.it/international/?lang=en</md:OrganizationURL><md:OrganizationURL xml:lang=\"fr\">https://www.infocert.it/international/?lang=fr</md:OrganizationURL><md:OrganizationURL xml:lang=\"de\">https://www.infocert.it/international/?lang=de</md:OrganizationURL></md:Organization></md:EntityDescriptor>\r\r",
    "provider": ""
  },
  "apiVersion": "1.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (76, '1ba5e273-053e-49b1-8abd-3d5bcb0998b8', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-25 11:13:09.300247+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\" standalone=\"no\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"_25b183c4c721960977003fb04ec600b4\" cacheDuration=\"P0Y0M30DT0H0M0.000S\" entityID=\"https://identity.infocert.it\"><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"#_25b183c4c721960977003fb04ec600b4\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>hKbiiLWanDYNT69FQLh4uWlI6rVdAfoNXltq8WE83No=</DigestValue></Reference></SignedInfo><SignatureValue>nqWCyBqw40iHn3OEF9qVnJIzX9xmTzoq3EE9pbpPtrrAnjBWKTI2GxCAH84oD7BArJ/oBWOEQ0iJzFLwdtJK56ly8MwFAiYdCuNm9wHd03gSGBMxaWbhQSfwkwRCmMbzxcXJGMhh4JECOdZ87KR861A+S2EPyWBHC9yx8iRZ4UtmrGpf3UWyFJsCEjCLZv+a/ld6WnkP43OqJhs84BQWrH+Z1QOy1GDDYe+sItvQ1BhOomDT6x+ZsrMntgAItF+1kQxJ5CPRzGkYb10vr0WYukAAfcQ46fJ7Jje5ZBG8heBd61wxwKfuDDt6MD191PLWHjgy6sgA6zwXikGkQsTeeA==</SignatureValue><KeyInfo><X509Data><X509Certificate>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</X509Certificate></X509Data></KeyInfo></Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlsso\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlsso\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio fisico\" Name=\"address\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Ragione o denominazione sociale\" Name=\"companyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Provincia di nascita\" Name=\"countyOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di nascita\" Name=\"dateOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio digitale\" Name=\"digitalAddress\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Indirizzo di posta elettronica\" Name=\"email\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di scadenza identita\" Name=\"expirationDate\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Cognome\" Name=\"familyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice fiscale\" Name=\"fiscalNumber\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sesso\" Name=\"gender\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Documento d''identita\" Name=\"idCard\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Partita IVA\" Name=\"ivaCode\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Numero di telefono mobile\" Name=\"mobilePhone\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Nome\" Name=\"name\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Luogo di nascita\" Name=\"placeOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sede legale\" Name=\"registeredOffice\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice identificativo SPID\" Name=\"spidCode\"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"it\">https://www.infocert.it</md:OrganizationURL><md:OrganizationURL xml:lang=\"en\">https://www.infocert.it/international/?lang=en</md:OrganizationURL><md:OrganizationURL xml:lang=\"fr\">https://www.infocert.it/international/?lang=fr</md:OrganizationURL><md:OrganizationURL xml:lang=\"de\">https://www.infocert.it/international/?lang=de</md:OrganizationURL></md:Organization></md:EntityDescriptor>\r\r",
    "provider": "aruba"
  },
  "apiVersion": "1.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (77, '2f6d7910-925a-43b1-8f2a-de05a23494af', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-25 11:13:34.425441+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<?xml version=\"1.0\" standalone=\"no\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"_25b183c4c721960977003fb04ec600b4\" cacheDuration=\"P0Y0M30DT0H0M0.000S\" entityID=\"https://identity.infocert.it\"><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"#_25b183c4c721960977003fb04ec600b4\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>hKbiiLWanDYNT69FQLh4uWlI6rVdAfoNXltq8WE83No=</DigestValue></Reference></SignedInfo><SignatureValue>nqWCyBqw40iHn3OEF9qVnJIzX9xmTzoq3EE9pbpPtrrAnjBWKTI2GxCAH84oD7BArJ/oBWOEQ0iJzFLwdtJK56ly8MwFAiYdCuNm9wHd03gSGBMxaWbhQSfwkwRCmMbzxcXJGMhh4JECOdZ87KR861A+S2EPyWBHC9yx8iRZ4UtmrGpf3UWyFJsCEjCLZv+a/ld6WnkP43OqJhs84BQWrH+Z1QOy1GDDYe+sItvQ1BhOomDT6x+ZsrMntgAItF+1kQxJ5CPRzGkYb10vr0WYukAAfcQ46fJ7Jje5ZBG8heBd61wxwKfuDDt6MD191PLWHjgy6sgA6zwXikGkQsTeeA==</SignatureValue><KeyInfo><X509Data><X509Certificate>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</X509Certificate></X509Data></KeyInfo></Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlsso\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlsso\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio fisico\" Name=\"address\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Ragione o denominazione sociale\" Name=\"companyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Provincia di nascita\" Name=\"countyOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di nascita\" Name=\"dateOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio digitale\" Name=\"digitalAddress\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Indirizzo di posta elettronica\" Name=\"email\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di scadenza identita\" Name=\"expirationDate\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Cognome\" Name=\"familyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice fiscale\" Name=\"fiscalNumber\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sesso\" Name=\"gender\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Documento d''identita\" Name=\"idCard\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Partita IVA\" Name=\"ivaCode\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Numero di telefono mobile\" Name=\"mobilePhone\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Nome\" Name=\"name\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Luogo di nascita\" Name=\"placeOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sede legale\" Name=\"registeredOffice\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice identificativo SPID\" Name=\"spidCode\"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"it\">https://www.infocert.it</md:OrganizationURL><md:OrganizationURL xml:lang=\"en\">https://www.infocert.it/international/?lang=en</md:OrganizationURL><md:OrganizationURL xml:lang=\"fr\">https://www.infocert.it/international/?lang=fr</md:OrganizationURL><md:OrganizationURL xml:lang=\"de\">https://www.infocert.it/international/?lang=de</md:OrganizationURL></md:Organization></md:EntityDescriptor>\r\r",
    "provider": "infocrt"
  },
  "apiVersion": "1.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (78, 'e83eaf02-5c3b-4822-a3b2-6dc8c138579d', 'GET', 'http://192.168.56.103:8888/api/prvd/sapienza/metadata/build', '2017-07-25 11:13:52.00219+02', '192.168.56.1', NULL);
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (79, '6b966026-6de5-45a8-9313-8f2d425376f9', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-25 11:14:34.676106+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<md0:EntityDescriptor xmlns:md0=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:md1=\"urn:oasis:names:tc:SAML:2.0:assertion\" entityID=\"http://www.uniroma1.it\">\n    <md0:SPSSODescriptor AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n        <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n<ds:SignedInfo>\n<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n<ds:Reference>\n<ds:Transforms>\n<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n</ds:Transforms>\n<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n<ds:DigestValue>klrPVhpd8iPsKa5P2uMQ8sLFrTpxyJ2Ln4MIViP5dnw=</ds:DigestValue>\n</ds:Reference>\n</ds:SignedInfo>\n<ds:SignatureValue>ZkeT9oD/gSsHBfI6VJ8rcWM2RETXMBk7XoPmnmg5NTTrY8HK3fvjxCaGoPjpCBgY\nc8tIYc6+d9vXcz4BmIZc1uiWuROO+Wzbulvb4deu5ljiJau8sAgEPlbg2MNuAwA9\neFIYm+jwoP4ziRNwLywKqHKk1L12c4zXfnxzkhIgAP1touhl3c96aYVUNlhKd7Dz\n/C2p64jCCv2f1yGIKheAebsWv+OL8hrXchchFZXH1zndekssO5LL/EFZQx+KBR9b\ncP+xjB4+PSGS55QcKEQO4aOm3FDTckw+AbdR5bip7ufhSa0nXv9VZcVNpLQTGwwc\ntOlr1B5X407dRxmjLCVEE6ZlRWmHIU/K3XEhae5zO0pB2fFpSNC7/0mUeCT2ayGZ\nZp36XT8JGTsbW5tX0VcQLbBo+xlzrnrl1ymSbDBi5iI/S4uhycHzVPNR3a9KUBi5\nKiIwlWYuLdEHMexTAwa9/tsoriBwz5xNr+SRRJ2prJNjgQk7do/jcc1dkISaApVK\nFXNZhf1kv4/Yu5mmANxS0ZB+CaAogQRZbLsCkM2X+IfuF1Jf4P0ZZdeSRwVghyPr\neLfWKNP3YbGIDHRqXG9ZeVktAgjQ36vppMQ8z6CZCyY6VzgBRYUJUb9x5sqs5uR6\n3qrH7+UpAN8wTSVJnyQ3aVaVY/bozfXEEBBFLwdJCno=</ds:SignatureValue>\n<ds:KeyInfo>\n<ds:X509Data>\n<ds:X509Certificate>MIIGljCCBH6gAwIBAgIJAO2VpEv6m6DWMA0GCSqGSIb3DQEBDQUAMIHBMQswCQYD\nVQQGEwJJVDENMAsGA1UECBMEUm9tZTENMAsGA1UEBxMEUm9tZTEnMCUGA1UEChMe\nVW5pdmVyc2l0eSBvZiBSb21lIExhIFNhcGllbnphMTAwLgYDVQQLEydJbmZvU2Fw\naWVuemEsIFNldHRvcmUgQ2FycmllcmUgU3R1ZGVudGkxFDASBgNVBAMTC1N0dWRl\nbnRpIENBMSMwIQYJKoZIhvcNAQkBFhRpbmZvc3R1ZEB1bmlyb21hMS5pdDAeFw0x\nNzA1MTgxNjA0MjNaFw0xODA1MTgxNjA0MjNaMIGmMQswCQYDVQQGEwJJVDENMAsG\nA1UECBMEUm9tZTENMAsGA1UEBxMEUm9tZTEnMCUGA1UEChMeVW5pdmVyc2l0eSBv\nZiBSb21lIExhIFNhcGllbnphMREwDwYDVQQLEwhJbmZvc3R1ZDEYMBYGA1UEAxMP\nd3d3LnVuaXJvbWExLml0MSMwIQYJKoZIhvcNAQkBFhRpbmZvc3R1ZEB1bmlyb21h\nMS5pdDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMmP1yM0qycjfu/k\nmT0TqRbiPWMCi9uYAIu5U5twhY1WEJ8lzP4UTmtg5PRfkIcf5HgIiOF5BZCFp4n5\nOwcnFxXXzoJcIgMpmdcAM2ozyPPhxqQYvKOxM8jBjN6uioG6D40M5j5Qr5sneK9a\nkWOYsbQ8t4LmyML3jMZKK4kfmkgb5ccE4fgHUvXmdOb+t4/jNXqIXpzbXZslexTD\n91EJua8Kc3Ro4iV1+F0I/zv4BfXnAX+OOBWw3+toAnA1vF+/DCafaa/sr9yvQIho\njXVqcerYnLK/0u0dNdU9JpvD0bNXTJmXbVJakNClW0i7k929PclqC7XaRb7C2WW9\nxwD4BH95gTN0pDI6f5XDf8XwTg3KI9K3Ni7m/VhYm3WMHOlFqpSXd5x/7bbD94SY\nF3qo3bYqxIrynALqeQ61ASsxusktLFxUw6MyMrptwfPRLCqhWzzxyQYR2PVekS5C\nQunI6GhF/7pQaPJmLYJIL9TRSTPCROodmrfumIvOdu958qmDpOOXg4bWp1OWszah\n7AAqy4O5/ef0yUR+yI39wV9dxabo8TWV1HyFCpDVXyr6oNTmheL30pX2WQx1qATG\ndshpFIAU4zflKMxc0tRk0c47rBmTMsocrveIk4HrQDUX8o3i0T4bwc0Y/tCrp9ze\nt/hFsGPRPncOWRy44xZ18OjRLWjNAgMBAAGjgakwgaYwCQYDVR0TBAIwADAsBglg\nhkgBhvhCAQ0EHxYdT3BlblNTTCBHZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0O\nBBYEFBNMl6pIuv5bcO0KXUXPoCEEuIKkMB8GA1UdIwQYMBaAFB9i8gxKs7VGd5QM\nlTBXkF3ffvLrMCsGA1UdEgQkMCKGIGh0dHA6Ly8xOTIuMTY4LjEwLjE4MC9zc2wv\nY2EuY3J0MA0GCSqGSIb3DQEBDQUAA4ICAQBVJC2IgPAzs/skjA0tRxPCDNuGln6c\naWf1YMaUyMRfrrmvVZRpcdPdfpL6aJfF8NSTlz1CzFOW41J2cPUBVEe38OVGJmqB\n00rpBUMUB6TRdiHDhiLVlfS/EkVRZomM/KxuxZyi13vjqQBUpcdvmqqeI5QxX3rG\n+29i/BzoW4aTg27d1SFLF1GG+9KuIShk05epSzZ2F+ndZHSwJ9lGYh0RQM00q2Wo\nrN/kGc0BOwJTdFM/gWtumEZgixLtkBSia5M0z/JiePR7C5gaYY2db1DXMLodzQoJ\nTRu0VA9ibN9SBCPg9P2peYzWyk8acdEVB+3AKBNFmoKiIaHh84U3JCh/u3lrEC06\nkdX9sKmIM4WJiXIFFlvS44peUmjpb0hZWlz/GA+2EeWNYm0dBHef50R2f6PPWuRv\nl1GyNne0Z7/RGQPcrI9TUEG0Dw6HQriSmTQWOaoAU8KlomDH+ChC5kbI/H4D3L2Y\nMyPa5iFuNe4RCPL7071B57r0q2WsIw8sHVX8zm04msbRZV/dPwZ/0mscMfdjdQzL\nnpdO7ZYj0dcwaZNFLbrFKmGOmFBTj6ygj4/b6Bd4U222mtMMR4u+Lck6quWCkHcC\ngoQW9TCAnIbu//URPCyA+pivyvwG+vy295xIAeaQYBtWWXOIKZttmbLBcmfx4KaD\nA9j3h4a3EzHoPQ==</ds:X509Certificate>\n</ds:X509Data>\n</ds:KeyInfo>\n</ds:Signature><md0:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIIGljCCBH6gAwIBAgIJAO2VpEv6m6DWMA0GCSqGSIb3DQEBDQUAMIHBMQswCQYDVQQGEwJJVDENMAsGA1UECBMEUm9tZTENMAsGA1UEBxMEUm9tZTEnMCUGA1UEChMeVW5pdmVyc2l0eSBvZiBSb21lIExhIFNhcGllbnphMTAwLgYDVQQLEydJbmZvU2FwaWVuemEsIFNldHRvcmUgQ2FycmllcmUgU3R1ZGVudGkxFDASBgNVBAMTC1N0dWRlbnRpIENBMSMwIQYJKoZIhvcNAQkBFhRpbmZvc3R1ZEB1bmlyb21hMS5pdDAeFw0xNzA1MTgxNjA0MjNaFw0xODA1MTgxNjA0MjNaMIGmMQswCQYDVQQGEwJJVDENMAsGA1UECBMEUm9tZTENMAsGA1UEBxMEUm9tZTEnMCUGA1UEChMeVW5pdmVyc2l0eSBvZiBSb21lIExhIFNhcGllbnphMREwDwYDVQQLEwhJbmZvc3R1ZDEYMBYGA1UEAxMPd3d3LnVuaXJvbWExLml0MSMwIQYJKoZIhvcNAQkBFhRpbmZvc3R1ZEB1bmlyb21hMS5pdDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMmP1yM0qycjfu/kmT0TqRbiPWMCi9uYAIu5U5twhY1WEJ8lzP4UTmtg5PRfkIcf5HgIiOF5BZCFp4n5OwcnFxXXzoJcIgMpmdcAM2ozyPPhxqQYvKOxM8jBjN6uioG6D40M5j5Qr5sneK9akWOYsbQ8t4LmyML3jMZKK4kfmkgb5ccE4fgHUvXmdOb+t4/jNXqIXpzbXZslexTD91EJua8Kc3Ro4iV1+F0I/zv4BfXnAX+OOBWw3+toAnA1vF+/DCafaa/sr9yvQIhojXVqcerYnLK/0u0dNdU9JpvD0bNXTJmXbVJakNClW0i7k929PclqC7XaRb7C2WW9xwD4BH95gTN0pDI6f5XDf8XwTg3KI9K3Ni7m/VhYm3WMHOlFqpSXd5x/7bbD94SYF3qo3bYqxIrynALqeQ61ASsxusktLFxUw6MyMrptwfPRLCqhWzzxyQYR2PVekS5CQunI6GhF/7pQaPJmLYJIL9TRSTPCROodmrfumIvOdu958qmDpOOXg4bWp1OWszah7AAqy4O5/ef0yUR+yI39wV9dxabo8TWV1HyFCpDVXyr6oNTmheL30pX2WQx1qATGdshpFIAU4zflKMxc0tRk0c47rBmTMsocrveIk4HrQDUX8o3i0T4bwc0Y/tCrp9zet/hFsGPRPncOWRy44xZ18OjRLWjNAgMBAAGjgakwgaYwCQYDVR0TBAIwADAsBglghkgBhvhCAQ0EHxYdT3BlblNTTCBHZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFBNMl6pIuv5bcO0KXUXPoCEEuIKkMB8GA1UdIwQYMBaAFB9i8gxKs7VGd5QMlTBXkF3ffvLrMCsGA1UdEgQkMCKGIGh0dHA6Ly8xOTIuMTY4LjEwLjE4MC9zc2wvY2EuY3J0MA0GCSqGSIb3DQEBDQUAA4ICAQBVJC2IgPAzs/skjA0tRxPCDNuGln6caWf1YMaUyMRfrrmvVZRpcdPdfpL6aJfF8NSTlz1CzFOW41J2cPUBVEe38OVGJmqB00rpBUMUB6TRdiHDhiLVlfS/EkVRZomM/KxuxZyi13vjqQBUpcdvmqqeI5QxX3rG+29i/BzoW4aTg27d1SFLF1GG+9KuIShk05epSzZ2F+ndZHSwJ9lGYh0RQM00q2WorN/kGc0BOwJTdFM/gWtumEZgixLtkBSia5M0z/JiePR7C5gaYY2db1DXMLodzQoJTRu0VA9ibN9SBCPg9P2peYzWyk8acdEVB+3AKBNFmoKiIaHh84U3JCh/u3lrEC06kdX9sKmIM4WJiXIFFlvS44peUmjpb0hZWlz/GA+2EeWNYm0dBHef50R2f6PPWuRvl1GyNne0Z7/RGQPcrI9TUEG0Dw6HQriSmTQWOaoAU8KlomDH+ChC5kbI/H4D3L2YMyPa5iFuNe4RCPL7071B57r0q2WsIw8sHVX8zm04msbRZV/dPwZ/0mscMfdjdQzLnpdO7ZYj0dcwaZNFLbrFKmGOmFBTj6ygj4/b6Bd4U222mtMMR4u+Lck6quWCkHcCgoQW9TCAnIbu//URPCyA+pivyvwG+vy295xIAeaQYBtWWXOIKZttmbLBcmfx4KaDA9j3h4a3EzHoPQ==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md0:KeyDescriptor><md0:KeyDescriptor use=\"encryption\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md0:KeyDescriptor><md0:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://www.uniroma1.it/spid/ssosignout\"/>\n        <md0:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md0:NameIDFormat>\n        <md0:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://www.uniroma1.it/spid/consume\" index=\"0\" isDefault=\"true\"/>\n        <md0:AttributeConsumingService index=\"0\">\n            <md0:ServiceName xml:lang=\"it\">Infostud</md0:ServiceName>\n            <md0:ServiceDescription xml:lang=\"it\">Infostud Login</md0:ServiceDescription>\n            <md0:RequestedAttribute FriendlyName=\"fefwe\" Name=\"fiscalNumber\" isRequired=\"true\">\n                <md1:AttributeValue>1</md1:AttributeValue>\n                <md1:AttributeValue>2</md1:AttributeValue>\n            </md0:RequestedAttribute>\n        </md0:AttributeConsumingService>\n    </md0:SPSSODescriptor>\n    <md0:Organization>\n        <md0:OrganizationName xml:lang=\"it\">Universita'' Sapienza</md0:OrganizationName>\n        <md0:OrganizationDisplayName xml:lang=\"it\">Universita'' degli Studi La Sapienza - Roma</md0:OrganizationDisplayName>\n        <md0:OrganizationURL xml:lang=\"it\">http://www.uniroma1.it</md0:OrganizationURL>\n    </md0:Organization>\n    <md0:ContactPerson contactType=\"support\">\n        <md0:GivenName>InfoSapienza</md0:GivenName>\n        <md0:EmailAddress>infostud@uniroma1.it</md0:EmailAddress>\n    </md0:ContactPerson>\n    <md0:ContactPerson contactType=\"technical\">\n        <md0:GivenName>InfoSapienza</md0:GivenName>\n        <md0:EmailAddress>infostud@uniroma1.it</md0:EmailAddress>\n    </md0:ContactPerson>\n</md0:EntityDescriptor>",
    "provider": "infocrt"
  },
  "apiVersion": "1.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (80, '5ee2a53f-48f0-495a-9443-d5b3a51a2de6', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-25 11:14:42.888091+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<md0:EntityDescriptor xmlns:md0=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:md1=\"urn:oasis:names:tc:SAML:2.0:assertion\" entityID=\"http://www.uniroma1.it\">\n    <md0:SPSSODescriptor AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n        <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n<ds:SignedInfo>\n<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n<ds:Reference>\n<ds:Transforms>\n<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n</ds:Transforms>\n<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n<ds:DigestValue>klrPVhpd8iPsKa5P2uMQ8sLFrTpxyJ2Ln4MIViP5dnw=</ds:DigestValue>\n</ds:Reference>\n</ds:SignedInfo>\n<ds:SignatureValue>ZkeT9oD/gSsHBfI6VJ8rcWM2RETXMBk7XoPmnmg5NTTrY8HK3fvjxCaGoPjpCBgY\nc8tIYc6+d9vXcz4BmIZc1uiWuROO+Wzbulvb4deu5ljiJau8sAgEPlbg2MNuAwA9\neFIYm+jwoP4ziRNwLywKqHKk1L12c4zXfnxzkhIgAP1touhl3c96aYVUNlhKd7Dz\n/C2p64jCCv2f1yGIKheAebsWv+OL8hrXchchFZXH1zndekssO5LL/EFZQx+KBR9b\ncP+xjB4+PSGS55QcKEQO4aOm3FDTckw+AbdR5bip7ufhSa0nXv9VZcVNpLQTGwwc\ntOlr1B5X407dRxmjLCVEE6ZlRWmHIU/K3XEhae5zO0pB2fFpSNC7/0mUeCT2ayGZ\nZp36XT8JGTsbW5tX0VcQLbBo+xlzrnrl1ymSbDBi5iI/S4uhycHzVPNR3a9KUBi5\nKiIwlWYuLdEHMexTAwa9/tsoriBwz5xNr+SRRJ2prJNjgQk7do/jcc1dkISaApVK\nFXNZhf1kv4/Yu5mmANxS0ZB+CaAogQRZbLsCkM2X+IfuF1Jf4P0ZZdeSRwVghyPr\neLfWKNP3YbGIDHRqXG9ZeVktAgjQ36vppMQ8z6CZCyY6VzgBRYUJUb9x5sqs5uR6\n3qrH7+UpAN8wTSVJnyQ3aVaVY/bozfXEEBBFLwdJCno=</ds:SignatureValue>\n<ds:KeyInfo>\n<ds:X509Data>\n<ds:X509Certificate>MIIGljCCBH6gAwIBAgIJAO2VpEv6m6DWMA0GCSqGSIb3DQEBDQUAMIHBMQswCQYD\nVQQGEwJJVDENMAsGA1UECBMEUm9tZTENMAsGA1UEBxMEUm9tZTEnMCUGA1UEChMe\nVW5pdmVyc2l0eSBvZiBSb21lIExhIFNhcGllbnphMTAwLgYDVQQLEydJbmZvU2Fw\naWVuemEsIFNldHRvcmUgQ2FycmllcmUgU3R1ZGVudGkxFDASBgNVBAMTC1N0dWRl\nbnRpIENBMSMwIQYJKoZIhvcNAQkBFhRpbmZvc3R1ZEB1bmlyb21hMS5pdDAeFw0x\nNzA1MTgxNjA0MjNaFw0xODA1MTgxNjA0MjNaMIGmMQswCQYDVQQGEwJJVDENMAsG\nA1UECBMEUm9tZTENMAsGA1UEBxMEUm9tZTEnMCUGA1UEChMeVW5pdmVyc2l0eSBv\nZiBSb21lIExhIFNhcGllbnphMREwDwYDVQQLEwhJbmZvc3R1ZDEYMBYGA1UEAxMP\nd3d3LnVuaXJvbWExLml0MSMwIQYJKoZIhvcNAQkBFhRpbmZvc3R1ZEB1bmlyb21h\nMS5pdDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMmP1yM0qycjfu/k\nmT0TqRbiPWMCi9uYAIu5U5twhY1WEJ8lzP4UTmtg5PRfkIcf5HgIiOF5BZCFp4n5\nOwcnFxXXzoJcIgMpmdcAM2ozyPPhxqQYvKOxM8jBjN6uioG6D40M5j5Qr5sneK9a\nkWOYsbQ8t4LmyML3jMZKK4kfmkgb5ccE4fgHUvXmdOb+t4/jNXqIXpzbXZslexTD\n91EJua8Kc3Ro4iV1+F0I/zv4BfXnAX+OOBWw3+toAnA1vF+/DCafaa/sr9yvQIho\njXVqcerYnLK/0u0dNdU9JpvD0bNXTJmXbVJakNClW0i7k929PclqC7XaRb7C2WW9\nxwD4BH95gTN0pDI6f5XDf8XwTg3KI9K3Ni7m/VhYm3WMHOlFqpSXd5x/7bbD94SY\nF3qo3bYqxIrynALqeQ61ASsxusktLFxUw6MyMrptwfPRLCqhWzzxyQYR2PVekS5C\nQunI6GhF/7pQaPJmLYJIL9TRSTPCROodmrfumIvOdu958qmDpOOXg4bWp1OWszah\n7AAqy4O5/ef0yUR+yI39wV9dxabo8TWV1HyFCpDVXyr6oNTmheL30pX2WQx1qATG\ndshpFIAU4zflKMxc0tRk0c47rBmTMsocrveIk4HrQDUX8o3i0T4bwc0Y/tCrp9ze\nt/hFsGPRPncOWRy44xZ18OjRLWjNAgMBAAGjgakwgaYwCQYDVR0TBAIwADAsBglg\nhkgBhvhCAQ0EHxYdT3BlblNTTCBHZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0O\nBBYEFBNMl6pIuv5bcO0KXUXPoCEEuIKkMB8GA1UdIwQYMBaAFB9i8gxKs7VGd5QM\nlTBXkF3ffvLrMCsGA1UdEgQkMCKGIGh0dHA6Ly8xOTIuMTY4LjEwLjE4MC9zc2wv\nY2EuY3J0MA0GCSqGSIb3DQEBDQUAA4ICAQBVJC2IgPAzs/skjA0tRxPCDNuGln6c\naWf1YMaUyMRfrrmvVZRpcdPdfpL6aJfF8NSTlz1CzFOW41J2cPUBVEe38OVGJmqB\n00rpBUMUB6TRdiHDhiLVlfS/EkVRZomM/KxuxZyi13vjqQBUpcdvmqqeI5QxX3rG\n+29i/BzoW4aTg27d1SFLF1GG+9KuIShk05epSzZ2F+ndZHSwJ9lGYh0RQM00q2Wo\nrN/kGc0BOwJTdFM/gWtumEZgixLtkBSia5M0z/JiePR7C5gaYY2db1DXMLodzQoJ\nTRu0VA9ibN9SBCPg9P2peYzWyk8acdEVB+3AKBNFmoKiIaHh84U3JCh/u3lrEC06\nkdX9sKmIM4WJiXIFFlvS44peUmjpb0hZWlz/GA+2EeWNYm0dBHef50R2f6PPWuRv\nl1GyNne0Z7/RGQPcrI9TUEG0Dw6HQriSmTQWOaoAU8KlomDH+ChC5kbI/H4D3L2Y\nMyPa5iFuNe4RCPL7071B57r0q2WsIw8sHVX8zm04msbRZV/dPwZ/0mscMfdjdQzL\nnpdO7ZYj0dcwaZNFLbrFKmGOmFBTj6ygj4/b6Bd4U222mtMMR4u+Lck6quWCkHcC\ngoQW9TCAnIbu//URPCyA+pivyvwG+vy295xIAeaQYBtWWXOIKZttmbLBcmfx4KaD\nA9j3h4a3EzHoPQ==</ds:X509Certificate>\n</ds:X509Data>\n</ds:KeyInfo>\n</ds:Signature><md0:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md0:KeyDescriptor><md0:KeyDescriptor use=\"encryption\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md0:KeyDescriptor><md0:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://www.uniroma1.it/spid/ssosignout\"/>\n        <md0:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md0:NameIDFormat>\n        <md0:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://www.uniroma1.it/spid/consume\" index=\"0\" isDefault=\"true\"/>\n        <md0:AttributeConsumingService index=\"0\">\n            <md0:ServiceName xml:lang=\"it\">Infostud</md0:ServiceName>\n            <md0:ServiceDescription xml:lang=\"it\">Infostud Login</md0:ServiceDescription>\n            <md0:RequestedAttribute FriendlyName=\"fefwe\" Name=\"fiscalNumber\" isRequired=\"true\">\n                <md1:AttributeValue>1</md1:AttributeValue>\n                <md1:AttributeValue>2</md1:AttributeValue>\n            </md0:RequestedAttribute>\n        </md0:AttributeConsumingService>\n    </md0:SPSSODescriptor>\n    <md0:Organization>\n        <md0:OrganizationName xml:lang=\"it\">Universita'' Sapienza</md0:OrganizationName>\n        <md0:OrganizationDisplayName xml:lang=\"it\">Universita'' degli Studi La Sapienza - Roma</md0:OrganizationDisplayName>\n        <md0:OrganizationURL xml:lang=\"it\">http://www.uniroma1.it</md0:OrganizationURL>\n    </md0:Organization>\n    <md0:ContactPerson contactType=\"support\">\n        <md0:GivenName>InfoSapienza</md0:GivenName>\n        <md0:EmailAddress>infostud@uniroma1.it</md0:EmailAddress>\n    </md0:ContactPerson>\n    <md0:ContactPerson contactType=\"technical\">\n        <md0:GivenName>InfoSapienza</md0:GivenName>\n        <md0:EmailAddress>infostud@uniroma1.it</md0:EmailAddress>\n    </md0:ContactPerson>\n</md0:EntityDescriptor>",
    "provider": "infocrt"
  },
  "apiVersion": "1.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (81, '94617ef8-f929-423d-9ade-d530f49d6593', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-25 11:14:51.342589+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<md0:EntityDescriptor xmlns:md0=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:md1=\"urn:oasis:names:tc:SAML:2.0:assertion\" entityID=\"http://www.uniroma1.it\">\n    <md0:SPSSODescriptor AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n        <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n<ds:SignedInfo>\n<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n<ds:Reference>\n<ds:Transforms>\n<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n</ds:Transforms>\n<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n<ds:DigestValue>klrPVhpd8iPsKa5P2uMQ8sLFrTpxyJ2Ln4MIViP5dnw=</ds:DigestValue>\n</ds:Reference>\n</ds:SignedInfo>\n<ds:SignatureValue>ZkeT9oD/gSsHBfI6VJ8rcWM2RETXMBk7XoPmnmg5NTTrY8HK3fvjxCaGoPjpCBgY\nc8tIYc6+d9vXcz4BmIZc1uiWuROO+Wzbulvb4deu5ljiJau8sAgEPlbg2MNuAwA9\neFIYm+jwoP4ziRNwLywKqHKk1L12c4zXfnxzkhIgAP1touhl3c96aYVUNlhKd7Dz\n/C2p64jCCv2f1yGIKheAebsWv+OL8hrXchchFZXH1zndekssO5LL/EFZQx+KBR9b\ncP+xjB4+PSGS55QcKEQO4aOm3FDTckw+AbdR5bip7ufhSa0nXv9VZcVNpLQTGwwc\ntOlr1B5X407dRxmjLCVEE6ZlRWmHIU/K3XEhae5zO0pB2fFpSNC7/0mUeCT2ayGZ\nZp36XT8JGTsbW5tX0VcQLbBo+xlzrnrl1ymSbDBi5iI/S4uhycHzVPNR3a9KUBi5\nKiIwlWYuLdEHMexTAwa9/tsoriBwz5xNr+SRRJ2prJNjgQk7do/jcc1dkISaApVK\nFXNZhf1kv4/Yu5mmANxS0ZB+CaAogQRZbLsCkM2X+IfuF1Jf4P0ZZdeSRwVghyPr\neLfWKNP3YbGIDHRqXG9ZeVktAgjQ36vppMQ8z6CZCyY6VzgBRYUJUb9x5sqs5uR6\n3qrH7+UpAN8wTSVJnyQ3aVaVY/bozfXEEBBFLwdJCno=</ds:SignatureValue>\n<ds:KeyInfo>\n<ds:X509Data>\n<ds:X509Certificate>MIIGljCCBH6gAwIBAgIJAO2VpEv6m6DWMA0GCSqGSIb3DQEBDQUAMIHBMQswCQYD\nVQQGEwJJVDENMAsGA1UECBMEUm9tZTENMAsGA1UEBxMEUm9tZTEnMCUGA1UEChMe\nVW5pdmVyc2l0eSBvZiBSb21lIExhIFNhcGllbnphMTAwLgYDVQQLEydJbmZvU2Fw\naWVuemEsIFNldHRvcmUgQ2FycmllcmUgU3R1ZGVudGkxFDASBgNVBAMTC1N0dWRl\nbnRpIENBMSMwIQYJKoZIhvcNAQkBFhRpbmZvc3R1ZEB1bmlyb21hMS5pdDAeFw0x\nNzA1MTgxNjA0MjNaFw0xODA1MTgxNjA0MjNaMIGmMQswCQYDVQQGEwJJVDENMAsG\nA1UECBMEUm9tZTENMAsGA1UEBxMEUm9tZTEnMCUGA1UEChMeVW5pdmVyc2l0eSBv\nZiBSb21lIExhIFNhcGllbnphMREwDwYDVQQLEwhJbmZvc3R1ZDEYMBYGA1UEAxMP\nd3d3LnVuaXJvbWExLml0MSMwIQYJKoZIhvcNAQkBFhRpbmZvc3R1ZEB1bmlyb21h\nMS5pdDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMmP1yM0qycjfu/k\nmT0TqRbiPWMCi9uYAIu5U5twhY1WEJ8lzP4UTmtg5PRfkIcf5HgIiOF5BZCFp4n5\nOwcnFxXXzoJcIgMpmdcAM2ozyPPhxqQYvKOxM8jBjN6uioG6D40M5j5Qr5sneK9a\nkWOYsbQ8t4LmyML3jMZKK4kfmkgb5ccE4fgHUvXmdOb+t4/jNXqIXpzbXZslexTD\n91EJua8Kc3Ro4iV1+F0I/zv4BfXnAX+OOBWw3+toAnA1vF+/DCafaa/sr9yvQIho\njXVqcerYnLK/0u0dNdU9JpvD0bNXTJmXbVJakNClW0i7k929PclqC7XaRb7C2WW9\nxwD4BH95gTN0pDI6f5XDf8XwTg3KI9K3Ni7m/VhYm3WMHOlFqpSXd5x/7bbD94SY\nF3qo3bYqxIrynALqeQ61ASsxusktLFxUw6MyMrptwfPRLCqhWzzxyQYR2PVekS5C\nQunI6GhF/7pQaPJmLYJIL9TRSTPCROodmrfumIvOdu958qmDpOOXg4bWp1OWszah\n7AAqy4O5/ef0yUR+yI39wV9dxabo8TWV1HyFCpDVXyr6oNTmheL30pX2WQx1qATG\ndshpFIAU4zflKMxc0tRk0c47rBmTMsocrveIk4HrQDUX8o3i0T4bwc0Y/tCrp9ze\nt/hFsGPRPncOWRy44xZ18OjRLWjNAgMBAAGjgakwgaYwCQYDVR0TBAIwADAsBglg\nhkgBhvhCAQ0EHxYdT3BlblNTTCBHZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0O\nBBYEFBNMl6pIuv5bcO0KXUXPoCEEuIKkMB8GA1UdIwQYMBaAFB9i8gxKs7VGd5QM\nlTBXkF3ffvLrMCsGA1UdEgQkMCKGIGh0dHA6Ly8xOTIuMTY4LjEwLjE4MC9zc2wv\nY2EuY3J0MA0GCSqGSIb3DQEBDQUAA4ICAQBVJC2IgPAzs/skjA0tRxPCDNuGln6c\naWf1YMaUyMRfrrmvVZRpcdPdfpL6aJfF8NSTlz1CzFOW41J2cPUBVEe38OVGJmqB\n00rpBUMUB6TRdiHDhiLVlfS/EkVRZomM/KxuxZyi13vjqQBUpcdvmqqeI5QxX3rG\n+29i/BzoW4aTg27d1SFLF1GG+9KuIShk05epSzZ2F+ndZHSwJ9lGYh0RQM00q2Wo\nrN/kGc0BOwJTdFM/gWtumEZgixLtkBSia5M0z/JiePR7C5gaYY2db1DXMLodzQoJ\nTRu0VA9ibN9SBCPg9P2peYzWyk8acdEVB+3AKBNFmoKiIaHh84U3JCh/u3lrEC06\nkdX9sKmIM4WJiXIFFlvS44peUmjpb0hZWlz/GA+2EeWNYm0dBHef50R2f6PPWuRv\nl1GyNne0Z7/RGQPcrI9TUEG0Dw6HQriSmTQWOaoAU8KlomDH+ChC5kbI/H4D3L2Y\nMyPa5iFuNe4RCPL7071B57r0q2WsIw8sHVX8zm04msbRZV/dPwZ/0mscMfdjdQzL\nnpdO7ZYj0dcwaZNFLbrFKmGOmFBTj6ygj4/b6Bd4U222mtMMR4u+Lck6quWCkHcC\ngoQW9TCAnIbu//URPCyA+pivyvwG+vy295xIAeaQYBtWWXOIKZttmbLBcmfx4KaD\nA9j3h4a3EzHoPQ==</ds:X509Certificate>\n</ds:X509Data>\n</ds:KeyInfo>\n</ds:Signature><md0:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md0:KeyDescriptor><md0:KeyDescriptor use=\"encryption\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md0:KeyDescriptor><md0:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://www.uniroma1.it/spid/ssosignout\"/>\n        <md0:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md0:NameIDFormat>\n        <md0:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://www.uniroma1.it/spid/consume\" index=\"0\" isDefault=\"true\"/>\n        <md0:AttributeConsumingService index=\"0\">\n            <md0:ServiceName xml:lang=\"it\">Infostud</md0:ServiceName>\n            <md0:ServiceDescription xml:lang=\"it\">Infostud Login</md0:ServiceDescription>\n            <md0:RequestedAttribute FriendlyName=\"fefwe\" Name=\"fiscalNumber\" isRequired=\"true\">\n                <md1:AttributeValue>1</md1:AttributeValue>\n                <md1:AttributeValue>2</md1:AttributeValue>\n            </md0:RequestedAttribute>\n        </md0:AttributeConsumingService>\n    </md0:SPSSODescriptor>\n    <md0:Organization>\n        <md0:OrganizationName xml:lang=\"it\">Universita'' Sapienza</md0:OrganizationName>\n        <md0:OrganizationDisplayName xml:lang=\"it\">Universita'' degli Studi La Sapienza - Roma</md0:OrganizationDisplayName>\n        <md0:OrganizationURL xml:lang=\"it\">http://www.uniroma1.it</md0:OrganizationURL>\n    </md0:Organization>\n    <md0:ContactPerson contactType=\"support\">\n        <md0:GivenName>InfoSapienza</md0:GivenName>\n        <md0:EmailAddress>infostud@uniroma1.it</md0:EmailAddress>\n    </md0:ContactPerson>\n    <md0:ContactPerson contactType=\"technical\">\n        <md0:GivenName>InfoSapienza</md0:GivenName>\n        <md0:EmailAddress>infostud@uniroma1.it</md0:EmailAddress>\n    </md0:ContactPerson>\n</md0:EntityDescriptor>",
    "provider": ""
  },
  "apiVersion": "1.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (82, '650a9f37-fb55-4fa8-b63b-2107d6dfba40', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-25 11:14:57.01054+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<md0:EntityDescriptor xmlns:md0=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:md1=\"urn:oasis:names:tc:SAML:2.0:assertion\" entityID=\"http://www.uniroma1.it\">\n    <md0:SPSSODescriptor AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n        <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n<ds:SignedInfo>\n<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n<ds:Reference>\n<ds:Transforms>\n<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n</ds:Transforms>\n<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n<ds:DigestValue>klrPVhpd8iPsKa5P2uMQ8sLFrTpxyJ2Ln4MIViP5dnw=</ds:DigestValue>\n</ds:Reference>\n</ds:SignedInfo>\n<ds:SignatureValue>ZkeT9oD/gSsHBfI6VJ8rcWM2RETXMBk7XoPmnmg5NTTrY8HK3fvjxCaGoPjpCBgY\nc8tIYc6+d9vXcz4BmIZc1uiWuROO+Wzbulvb4deu5ljiJau8sAgEPlbg2MNuAwA9\neFIYm+jwoP4ziRNwLywKqHKk1L12c4zXfnxzkhIgAP1touhl3c96aYVUNlhKd7Dz\n/C2p64jCCv2f1yGIKheAebsWv+OL8hrXchchFZXH1zndekssO5LL/EFZQx+KBR9b\ncP+xjB4+PSGS55QcKEQO4aOm3FDTckw+AbdR5bip7ufhSa0nXv9VZcVNpLQTGwwc\ntOlr1B5X407dRxmjLCVEE6ZlRWmHIU/K3XEhae5zO0pB2fFpSNC7/0mUeCT2ayGZ\nZp36XT8JGTsbW5tX0VcQLbBo+xlzrnrl1ymSbDBi5iI/S4uhycHzVPNR3a9KUBi5\nKiIwlWYuLdEHMexTAwa9/tsoriBwz5xNr+SRRJ2prJNjgQk7do/jcc1dkISaApVK\nFXNZhf1kv4/Yu5mmANxS0ZB+CaAogQRZbLsCkM2X+IfuF1Jf4P0ZZdeSRwVghyPr\neLfWKNP3YbGIDHRqXG9ZeVktAgjQ36vppMQ8z6CZCyY6VzgBRYUJUb9x5sqs5uR6\n3qrH7+UpAN8wTSVJnyQ3aVaVY/bozfXEEBBFLwdJCno=</ds:SignatureValue>\n<ds:KeyInfo>\n<ds:X509Data>\n<ds:X509Certificate>MIIGljCCBH6gAwIBAgIJAO2VpEv6m6DWMA0GCSqGSIb3DQEBDQUAMIHBMQswCQYD\nVQQGEwJJVDENMAsGA1UECBMEUm9tZTENMAsGA1UEBxMEUm9tZTEnMCUGA1UEChMe\nVW5pdmVyc2l0eSBvZiBSb21lIExhIFNhcGllbnphMTAwLgYDVQQLEydJbmZvU2Fw\naWVuemEsIFNldHRvcmUgQ2FycmllcmUgU3R1ZGVudGkxFDASBgNVBAMTC1N0dWRl\nbnRpIENBMSMwIQYJKoZIhvcNAQkBFhRpbmZvc3R1ZEB1bmlyb21hMS5pdDAeFw0x\nNzA1MTgxNjA0MjNaFw0xODA1MTgxNjA0MjNaMIGmMQswCQYDVQQGEwJJVDENMAsG\nA1UECBMEUm9tZTENMAsGA1UEBxMEUm9tZTEnMCUGA1UEChMeVW5pdmVyc2l0eSBv\nZiBSb21lIExhIFNhcGllbnphMREwDwYDVQQLEwhJbmZvc3R1ZDEYMBYGA1UEAxMP\nd3d3LnVuaXJvbWExLml0MSMwIQYJKoZIhvcNAQkBFhRpbmZvc3R1ZEB1bmlyb21h\nMS5pdDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMmP1yM0qycjfu/k\nmT0TqRbiPWMCi9uYAIu5U5twhY1WEJ8lzP4UTmtg5PRfkIcf5HgIiOF5BZCFp4n5\nOwcnFxXXzoJcIgMpmdcAM2ozyPPhxqQYvKOxM8jBjN6uioG6D40M5j5Qr5sneK9a\nkWOYsbQ8t4LmyML3jMZKK4kfmkgb5ccE4fgHUvXmdOb+t4/jNXqIXpzbXZslexTD\n91EJua8Kc3Ro4iV1+F0I/zv4BfXnAX+OOBWw3+toAnA1vF+/DCafaa/sr9yvQIho\njXVqcerYnLK/0u0dNdU9JpvD0bNXTJmXbVJakNClW0i7k929PclqC7XaRb7C2WW9\nxwD4BH95gTN0pDI6f5XDf8XwTg3KI9K3Ni7m/VhYm3WMHOlFqpSXd5x/7bbD94SY\nF3qo3bYqxIrynALqeQ61ASsxusktLFxUw6MyMrptwfPRLCqhWzzxyQYR2PVekS5C\nQunI6GhF/7pQaPJmLYJIL9TRSTPCROodmrfumIvOdu958qmDpOOXg4bWp1OWszah\n7AAqy4O5/ef0yUR+yI39wV9dxabo8TWV1HyFCpDVXyr6oNTmheL30pX2WQx1qATG\ndshpFIAU4zflKMxc0tRk0c47rBmTMsocrveIk4HrQDUX8o3i0T4bwc0Y/tCrp9ze\nt/hFsGPRPncOWRy44xZ18OjRLWjNAgMBAAGjgakwgaYwCQYDVR0TBAIwADAsBglg\nhkgBhvhCAQ0EHxYdT3BlblNTTCBHZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0O\nBBYEFBNMl6pIuv5bcO0KXUXPoCEEuIKkMB8GA1UdIwQYMBaAFB9i8gxKs7VGd5QM\nlTBXkF3ffvLrMCsGA1UdEgQkMCKGIGh0dHA6Ly8xOTIuMTY4LjEwLjE4MC9zc2wv\nY2EuY3J0MA0GCSqGSIb3DQEBDQUAA4ICAQBVJC2IgPAzs/skjA0tRxPCDNuGln6c\naWf1YMaUyMRfrrmvVZRpcdPdfpL6aJfF8NSTlz1CzFOW41J2cPUBVEe38OVGJmqB\n00rpBUMUB6TRdiHDhiLVlfS/EkVRZomM/KxuxZyi13vjqQBUpcdvmqqeI5QxX3rG\n+29i/BzoW4aTg27d1SFLF1GG+9KuIShk05epSzZ2F+ndZHSwJ9lGYh0RQM00q2Wo\nrN/kGc0BOwJTdFM/gWtumEZgixLtkBSia5M0z/JiePR7C5gaYY2db1DXMLodzQoJ\nTRu0VA9ibN9SBCPg9P2peYzWyk8acdEVB+3AKBNFmoKiIaHh84U3JCh/u3lrEC06\nkdX9sKmIM4WJiXIFFlvS44peUmjpb0hZWlz/GA+2EeWNYm0dBHef50R2f6PPWuRv\nl1GyNne0Z7/RGQPcrI9TUEG0Dw6HQriSmTQWOaoAU8KlomDH+ChC5kbI/H4D3L2Y\nMyPa5iFuNe4RCPL7071B57r0q2WsIw8sHVX8zm04msbRZV/dPwZ/0mscMfdjdQzL\nnpdO7ZYj0dcwaZNFLbrFKmGOmFBTj6ygj4/b6Bd4U222mtMMR4u+Lck6quWCkHcC\ngoQW9TCAnIbu//URPCyA+pivyvwG+vy295xIAeaQYBtWWXOIKZttmbLBcmfx4KaD\nA9j3h4a3EzHoPQ==</ds:X509Certificate>\n</ds:X509Data>\n</ds:KeyInfo>\n</ds:Signature><md0:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md0:KeyDescriptor><md0:KeyDescriptor use=\"encryption\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md0:KeyDescriptor><md0:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://www.uniroma1.it/spid/ssosignout\"/>\n        <md0:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md0:NameIDFormat>\n        <md0:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://www.uniroma1.it/spid/consume\" index=\"0\" isDefault=\"true\"/>\n        <md0:AttributeConsumingService index=\"0\">\n            <md0:ServiceName xml:lang=\"it\">Infostud</md0:ServiceName>\n            <md0:ServiceDescription xml:lang=\"it\">Infostud Login</md0:ServiceDescription>\n            <md0:RequestedAttribute FriendlyName=\"fefwe\" Name=\"fiscalNumber\" isRequired=\"true\">\n                <md1:AttributeValue>1</md1:AttributeValue>\n                <md1:AttributeValue>2</md1:AttributeValue>\n            </md0:RequestedAttribute>\n        </md0:AttributeConsumingService>\n    </md0:SPSSODescriptor>\n    <md0:Organization>\n        <md0:OrganizationName xml:lang=\"it\">Universita'' Sapienza</md0:OrganizationName>\n        <md0:OrganizationDisplayName xml:lang=\"it\">Universita'' degli Studi La Sapienza - Roma</md0:OrganizationDisplayName>\n        <md0:OrganizationURL xml:lang=\"it\">http://www.uniroma1.it</md0:OrganizationURL>\n    </md0:Organization>\n    <md0:ContactPerson contactType=\"support\">\n        <md0:GivenName>InfoSapienza</md0:GivenName>\n        <md0:EmailAddress>infostud@uniroma1.it</md0:EmailAddress>\n    </md0:ContactPerson>\n    <md0:ContactPerson contactType=\"technical\">\n        <md0:GivenName>InfoSapienza</md0:GivenName>\n        <md0:EmailAddress>infostud@uniroma1.it</md0:EmailAddress>\n    </md0:ContactPerson>\n</md0:EntityDescriptor>",
    "provider": "sapienza"
  },
  "apiVersion": "1.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (83, 'ec79bfbc-6add-4e47-b855-e34b8274bf9b', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-25 11:15:41.526365+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<ns0:AuthnRequest xmlns:md1=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:ns0=\"urn:oasis:names:tc:SAML:2.0:protocol\" AssertionConsumerServiceURL=\"http://www.uniroma1.it/spid/consume\" AttributeConsumingServiceIndex=\"0\" Destination=\"https://posteid.poste.it/jod-fs/ssoserviceredirect\" ForceAuthn=\"true\" ID=\"ONELOGIN_301a7c49121d01c9f38f38ae762faba2f4f7741a\" IssueInstant=\"2017-06-15T18:08:23Z\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" ProviderName=\"Universit&#224; degli Studi La Sapienza - Roma\" Version=\"2.0\">\n    <md1:Issuer Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\" NameQualifier=\"http://www.uniroma1.it\">http://www.uniroma1.it</md1:Issuer><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n<ds:SignedInfo>\n<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n<ds:Reference URI=\"#ONELOGIN_301a7c49121d01c9f38f38ae762faba2f4f7741a\">\n<ds:Transforms>\n<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n</ds:Transforms>\n<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n<ds:DigestValue>UL3eQ+6uszJ47fM+TiidruslIPtgquK9+GC5asVp3Nk=</ds:DigestValue>\n</ds:Reference>\n</ds:SignedInfo>\n<ds:SignatureValue>APOPPdzdwNMqntgUIdgVfW29XjcbP1bzFEwM9liu2EJqXwLjT+uSBvh36mKAfEzL\n9Ti5rLsNUy/a+QbFV4P+3dhQpSXm74bSGkP4vAsSE5GSra5DyzBtjBGfensgIJ/W\nVAUihh5rDwv0wSaX7bgELD7lX9/5MA9GFPCffrpC5JjRnCSCRpT9pbFinUkK9ad+\nv9+hwhjY6FQpKMt29O+qEQxs0XqoJHk3yuLx8LOX7GbX1p0D/di3mSjNNfT6lnYX\ndgCo5zt3FHJtSsbEk3viC4or8OHxxY2nlsbLR0fBjS9UXTzKAjS9+XNA1dyzzyyg\nZech7yMMX3q3G8Q3TWBjkQ==</ds:SignatureValue>\n<ds:KeyInfo>\n<ds:X509Data>\n<ds:X509Certificate>MIIEfjCCA2agAwIBAgIRALKXjUHMvme0AgDw3FFF630wDQYJKoZIhvcNAQEFBQAw\nNjELMAkGA1UEBhMCTkwxDzANBgNVBAoTBlRFUkVOQTEWMBQGA1UEAxMNVEVSRU5B\nIFNTTCBDQTAeFw0xNDA3MTYwMDAwMDBaFw0xNzA3MTUyMzU5NTlaMEYxITAfBgNV\nBAsTGERvbWFpbiBDb250cm9sIFZhbGlkYXRlZDEhMB8GA1UEAxMYd3d3LnN0dWRl\nbnRpLnVuaXJvbWExLml0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\nnDzHJbTiPbx1ZKXbUxfEaGRVzKiVG5VttqWiy9DCrOL0nZB9VBFuz81vXwev+XPF\nPIwXAGz/T0upf9t4m6z5ivGQt4iJSJQVG2gyqvt7sJgyw3eP2axK3vQT0mDtxSvR\njo8HM7eQHjwGTPF45WKz8ULx9qvRAI66Mn8uBhquH/uCGcmgBe0t6FPAd6rN1FMb\nF5GkEhEZn/NkU3fVuMRgtajRgT4f1mxouLHBrU872HBlaMvS1fhIJ2/tga/Hh98b\n2TDVP7n0lUTzWhxKUAdCyxEEw3Oyhwk6dYSo7RtZiOZwCjn/fFbk5W7tqKMeVi8v\nx4OXQ7pn2OrzAjhTW5qEMQIDAQABo4IBdTCCAXEwHwYDVR0jBBgwFoAUDL2TaAzz\n3qujSWsrN1dH6pDjue0wHQYDVR0OBBYEFH8aPwSyCQMXxS0jPz1+HptjvIS3MA4G\nA1UdDwEB/wQEAwIFoDAMBgNVHRMBAf8EAjAAMB0GA1UdJQQWMBQGCCsGAQUFBwMB\nBggrBgEFBQcDAjAiBgNVHSAEGzAZMA0GCysGAQQBsjEBAgIdMAgGBmeBDAECATA6\nBgNVHR8EMzAxMC+gLaArhilodHRwOi8vY3JsLnRjcy50ZXJlbmEub3JnL1RFUkVO\nQVNTTENBLmNybDBtBggrBgEFBQcBAQRhMF8wNQYIKwYBBQUHMAKGKWh0dHA6Ly9j\ncnQudGNzLnRlcmVuYS5vcmcvVEVSRU5BU1NMQ0EuY3J0MCYGCCsGAQUFBzABhhpo\ndHRwOi8vb2NzcC50Y3MudGVyZW5hLm9yZzAjBgNVHREEHDAaghh3d3cuc3R1ZGVu\ndGkudW5pcm9tYTEuaXQwDQYJKoZIhvcNAQEFBQADggEBAGKifcrUnqIqYhE4RnED\nmORKD/B0FK6ePIz6ddLaQ5cuMNiYPUK3N5gwHKstNJJADxlgMZcQCNlqtcoWRz8y\nVIW9+HvWdDV0rg46xb0fXgcEAP9qeg9B8+AXaRWw4zg355ROVLUB2wxU5xOlEG7K\n1dUB5IVtJlGq+YLobyGfTogKX85ahSLWdPKfeZwFUqhbSaaDvrYTyk+d4l52soul\nwMN/HWLFIqzPjZIbTwoph+Be+T3hIUQFRDg3wFAbHCxQY/yKQJYBxsJOC4Sfq5fa\ngH4woldPxHLiA+DXoHGmH2T4Ni3/PvjwjIDji7+MfdW1loW2beYfFdVDMGaCYStO\n+xc=</ds:X509Certificate>\n</ds:X509Data>\n</ds:KeyInfo>\n</ds:Signature>\n    <ns0:NameIDPolicy AllowCreate=\"true\" Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\"/>\n     <ns0:RequestedAuthnContext Comparison=\"minimum\"><md1:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:SpidL1</md1:AuthnContextClassRef>    </ns0:RequestedAuthnContext>\n</ns0:AuthnRequest>",
    "provider": "sapienza"
  },
  "apiVersion": "1.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (84, '31db801f-dfa8-4450-8ba8-385393dd60d9', 'GET', 'http://192.168.56.103:8888/api/prvd/sapienza/authnreq/build?idp=pt&attrindex=0&binding=redirect', '2017-07-25 11:16:10.619411+02', '192.168.56.1', NULL);
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (85, 'afee7ba8-3aa7-44ba-842b-434b85cfe765', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-25 11:16:41.039076+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<ns0:AuthnRequest xmlns:md1=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:ns0=\"urn:oasis:names:tc:SAML:2.0:protocol\" AssertionConsumerServiceURL=\"http://www.uniroma1.it/spid/consume\" AttributeConsumingServiceIndex=\"0\" Destination=\"https://posteid.poste.it/jod-fs/ssoserviceredirect\" ForceAuthn=\"true\" ID=\"ONELOGIN_18c0544b42bb91769fe826093cfaf21ce62134e6\" IssueInstant=\"2017-07-25T09:16:10Z\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" ProviderName=\"Universita'' degli Studi La Sapienza - Roma\" Version=\"2.0\">\n    <md1:Issuer Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\" NameQualifier=\"http://www.uniroma1.it\">http://www.uniroma1.it</md1:Issuer><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n<ds:SignedInfo>\n<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n<ds:Reference URI=\"#ONELOGIN_18c0544b42bb91769fe826093cfaf21ce62134e6\">\n<ds:Transforms>\n<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n</ds:Transforms>\n<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n<ds:DigestValue>MapCNSCalr0jgd58Dt+Arn5A7SJVVJW6txjUmwXY+Os=</ds:DigestValue>\n</ds:Reference>\n</ds:SignedInfo>\n<ds:SignatureValue>VIYGHq82Abrzwoor/wcfIHiGV6v9WVsf4YVrU9fZU8Xd1rK09QTJfTDaUDn+t0zc\n1kkZxS1cvnW4BuMIFVtUa25MWfByq8uc2AvZUctaXNkFyuCyK6HEkJPHB2WULx9D\nlS1VLl+aUhLEMheOxKP+3byhga1ArilRxcx/MRCvjWISFjHGeeFII2ceJFrzgQck\n+OBLbYvBcOVPLLEnLPOd050Vh+OHzzTahPc/CDmsIyeTA2Ok9xS+2B4kszhpBiw/\nPHnAMhjPA4TP+PuCfehszsLqJ4hYexHL9fsJ1w/HPXGXg/QfeXGS02Xst+bf0Xw6\niDVrcyQuC5icH/NFHbrQJeC/pOg23MDvXgx4Nv0+Y8YU6FMb9uB4Fyfdul5RVQUd\nUoIXzQ71OMB4nVtBb2X61QtDxR/RYyCWe+8+gmh0WUU0HCni80T0GR/cP09pYCvw\nusXtDZUfAPAOJ7a+0VKMfR609KLLvIPRsI60kdNiAxFVWZ4W9CRqooFCctqPPjQC\nS2zbJocJzz/4m/cQp6FWpgYYziU2RO+gdxK/AmFQJmhA3tKD04jqAI9dCZp9xatt\nFWDbcnJsLvU+4Ol+vQQ/vDiD5e+nFV+QEHKICtPiOcICQcUwmXbjjMWpX46s0GpN\n/Z0h7ux15mEHZ9dAU1XYRPtMAxneBCaijd6DHuJNT08=</ds:SignatureValue>\n<ds:KeyInfo>\n<ds:X509Data>\n<ds:X509Certificate>MIIGljCCBH6gAwIBAgIJAO2VpEv6m6DWMA0GCSqGSIb3DQEBDQUAMIHBMQswCQYD\nVQQGEwJJVDENMAsGA1UECBMEUm9tZTENMAsGA1UEBxMEUm9tZTEnMCUGA1UEChMe\nVW5pdmVyc2l0eSBvZiBSb21lIExhIFNhcGllbnphMTAwLgYDVQQLEydJbmZvU2Fw\naWVuemEsIFNldHRvcmUgQ2FycmllcmUgU3R1ZGVudGkxFDASBgNVBAMTC1N0dWRl\nbnRpIENBMSMwIQYJKoZIhvcNAQkBFhRpbmZvc3R1ZEB1bmlyb21hMS5pdDAeFw0x\nNzA1MTgxNjA0MjNaFw0xODA1MTgxNjA0MjNaMIGmMQswCQYDVQQGEwJJVDENMAsG\nA1UECBMEUm9tZTENMAsGA1UEBxMEUm9tZTEnMCUGA1UEChMeVW5pdmVyc2l0eSBv\nZiBSb21lIExhIFNhcGllbnphMREwDwYDVQQLEwhJbmZvc3R1ZDEYMBYGA1UEAxMP\nd3d3LnVuaXJvbWExLml0MSMwIQYJKoZIhvcNAQkBFhRpbmZvc3R1ZEB1bmlyb21h\nMS5pdDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMmP1yM0qycjfu/k\nmT0TqRbiPWMCi9uYAIu5U5twhY1WEJ8lzP4UTmtg5PRfkIcf5HgIiOF5BZCFp4n5\nOwcnFxXXzoJcIgMpmdcAM2ozyPPhxqQYvKOxM8jBjN6uioG6D40M5j5Qr5sneK9a\nkWOYsbQ8t4LmyML3jMZKK4kfmkgb5ccE4fgHUvXmdOb+t4/jNXqIXpzbXZslexTD\n91EJua8Kc3Ro4iV1+F0I/zv4BfXnAX+OOBWw3+toAnA1vF+/DCafaa/sr9yvQIho\njXVqcerYnLK/0u0dNdU9JpvD0bNXTJmXbVJakNClW0i7k929PclqC7XaRb7C2WW9\nxwD4BH95gTN0pDI6f5XDf8XwTg3KI9K3Ni7m/VhYm3WMHOlFqpSXd5x/7bbD94SY\nF3qo3bYqxIrynALqeQ61ASsxusktLFxUw6MyMrptwfPRLCqhWzzxyQYR2PVekS5C\nQunI6GhF/7pQaPJmLYJIL9TRSTPCROodmrfumIvOdu958qmDpOOXg4bWp1OWszah\n7AAqy4O5/ef0yUR+yI39wV9dxabo8TWV1HyFCpDVXyr6oNTmheL30pX2WQx1qATG\ndshpFIAU4zflKMxc0tRk0c47rBmTMsocrveIk4HrQDUX8o3i0T4bwc0Y/tCrp9ze\nt/hFsGPRPncOWRy44xZ18OjRLWjNAgMBAAGjgakwgaYwCQYDVR0TBAIwADAsBglg\nhkgBhvhCAQ0EHxYdT3BlblNTTCBHZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0O\nBBYEFBNMl6pIuv5bcO0KXUXPoCEEuIKkMB8GA1UdIwQYMBaAFB9i8gxKs7VGd5QM\nlTBXkF3ffvLrMCsGA1UdEgQkMCKGIGh0dHA6Ly8xOTIuMTY4LjEwLjE4MC9zc2wv\nY2EuY3J0MA0GCSqGSIb3DQEBDQUAA4ICAQBVJC2IgPAzs/skjA0tRxPCDNuGln6c\naWf1YMaUyMRfrrmvVZRpcdPdfpL6aJfF8NSTlz1CzFOW41J2cPUBVEe38OVGJmqB\n00rpBUMUB6TRdiHDhiLVlfS/EkVRZomM/KxuxZyi13vjqQBUpcdvmqqeI5QxX3rG\n+29i/BzoW4aTg27d1SFLF1GG+9KuIShk05epSzZ2F+ndZHSwJ9lGYh0RQM00q2Wo\nrN/kGc0BOwJTdFM/gWtumEZgixLtkBSia5M0z/JiePR7C5gaYY2db1DXMLodzQoJ\nTRu0VA9ibN9SBCPg9P2peYzWyk8acdEVB+3AKBNFmoKiIaHh84U3JCh/u3lrEC06\nkdX9sKmIM4WJiXIFFlvS44peUmjpb0hZWlz/GA+2EeWNYm0dBHef50R2f6PPWuRv\nl1GyNne0Z7/RGQPcrI9TUEG0Dw6HQriSmTQWOaoAU8KlomDH+ChC5kbI/H4D3L2Y\nMyPa5iFuNe4RCPL7071B57r0q2WsIw8sHVX8zm04msbRZV/dPwZ/0mscMfdjdQzL\nnpdO7ZYj0dcwaZNFLbrFKmGOmFBTj6ygj4/b6Bd4U222mtMMR4u+Lck6quWCkHcC\ngoQW9TCAnIbu//URPCyA+pivyvwG+vy295xIAeaQYBtWWXOIKZttmbLBcmfx4KaD\nA9j3h4a3EzHoPQ==</ds:X509Certificate>\n</ds:X509Data>\n</ds:KeyInfo>\n</ds:Signature>\n    <ns0:NameIDPolicy AllowCreate=\"true\" Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\"/>\n     <ns0:RequestedAuthnContext Comparison=\"minimum\"><md1:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:SpidL1</md1:AuthnContextClassRef>    </ns0:RequestedAuthnContext>\n</ns0:AuthnRequest>",
    "provider": "sapienza"
  },
  "apiVersion": "1.1"
}');
INSERT INTO requests ("ID", cod_request, http_verb, url, date, client, request) VALUES (86, 'bf6e2e34-a5a4-40f5-a402-80267b55108d', 'POST', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-25 11:16:49.448174+02', '192.168.56.1', '{
  "id": null,
  "request": {
    "assertion": "<ns0:AuthnRequest xmlns:md1=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:ns0=\"urn:oasis:names:tc:SAML:2.0:protocol\" AssertionConsumerServiceURL=\"http://www.uniroma1.it/spid/consume\" AttributeConsumingServiceIndex=\"0\" Destination=\"https://posteid.poste.it/jod-fs/ssoserviceredirect\" ForceAuthn=\"true\" ID=\"ONELOGIN_18c0544b42bb91769fe826093cfaf21ce62134e6\" IssueInstant=\"2017-07-25T09:16:10Z\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" ProviderName=\"Universita'' degli Studi La Sapienza - Roma\" Version=\"2.0\">\n    <md1:Issuer Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\" NameQualifier=\"http://www.uniroma1.it\">http://www.uniroma1.it</md1:Issuer><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n<ds:SignedInfo>\n<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n<ds:Reference URI=\"#ONELOGIN_18c0544b42bb91769fe826093cfaf21ce62134e6\">\n<ds:Transforms>\n<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n</ds:Transforms>\n<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n<ds:DigestValue>MapCNSCalr0jgd58Dt+Arn5A7SJVVJW6txjUmwXY+Os=</ds:DigestValue>\n</ds:Reference>\n</ds:SignedInfo>\n<ds:SignatureValue>VIYGHq82Abrzwoor/wcfIHiGV6v9WVsf4YVrU9fZU8Xd1rK09QTJfTDaUDn+t0zc\n1kkZxS1cvnW4BuMIFVtUa25MWfByq8uc2AvZUctaXNkFyuCyK6HEkJPHB2WULx9D\nlS1VLl+aUhLEMheOxKP+3byhga1ArilRxcx/MRCvjWISFjHGeeFII2ceJFrzgQck\n+OBLbYvBcOVPLLEnLPOd050Vh+OHzzTahPc/CDmsIyeTA2Ok9xS+2B4kszhpBiw/\nPHnAMhjPA4TP+PuCfehszsLqJ4hYexHL9fsJ1w/HPXGXg/QfeXGS02Xst+bf0Xw6\niDVrcyQuC5icH/NFHbrQJeC/pOg23MDvXgx4Nv0+Y8YU6FMb9uB4Fyfdul5RVQUd\nUoIXzQ71OMB4nVtBb2X61QtDxR/RYyCWe+8+gmh0WUU0HCni80T0GR/cP09pYCvw\nusXtDZUfAPAOJ7a+0VKMfR609KLLvIPRsI60kdNiAxFVWZ4W9CRqooFCctqPPjQC\nS2zbJocJzz/4m/cQp6FWpgYYziU2RO+gdxK/AmFQJmhA3tKD04jqAI9dCZp9xatt\nFWDbcnJsLvU+4Ol+vQQ/vDiD5e+nFV+QEHKICtPiOcICQcUwmXbjjMWpX46s0GpN\n/Z0h7ux15mEHZ9dAU1XYRPtMAxneBCaijd6DHuJNT08=</ds:SignatureValue>\n<ds:KeyInfo>\n<ds:X509Data>\n<ds:X509Certificate>MIIGljCCBH6gAwIBAgIJAO2VpEv6m6DWMA0GCSqGSIb3DQEBDQUAMIHBMQswCQYD\nVQQGEwJJVDENMAsGA1UECBMEUm9tZTENMAsGA1UEBxMEUm9tZTEnMCUGA1UEChMe\nVW5pdmVyc2l0eSBvZiBSb21lIExhIFNhcGllbnphMTAwLgYDVQQLEydJbmZvU2Fw\naWVuemEsIFNldHRvcmUgQ2FycmllcmUgU3R1ZGVudGkxFDASBgNVBAMTC1N0dWRl\nbnRpIENBMSMwIQYJKoZIhvcNAQkBFhRpbmZvc3R1ZEB1bmlyb21hMS5pdDAeFw0x\nNzA1MTgxNjA0MjNaFw0xODA1MTgxNjA0MjNaMIGmMQswCQYDVQQGEwJJVDENMAsG\nA1UECBMEUm9tZTENMAsGA1UEBxMEUm9tZTEnMCUGA1UEChMeVW5pdmVyc2l0eSBv\nZiBSb21lIExhIFNhcGllbnphMREwDwYDVQQLEwhJbmZvc3R1ZDEYMBYGA1UEAxMP\nd3d3LnVuaXJvbWExLml0MSMwIQYJKoZIhvcNAQkBFhRpbmZvc3R1ZEB1bmlyb21h\nMS5pdDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMmP1yM0qycjfu/k\nmT0TqRbiPWMCi9uYAIu5U5twhY1WEJ8lzP4UTmtg5PRfkIcf5HgIiOF5BZCFp4n5\nOwcnFxXXzoJcIgMpmdcAM2ozyPPhxqQYvKOxM8jBjN6uioG6D40M5j5Qr5sneK9a\nkWOYsbQ8t4LmyML3jMZKK4kfmkgb5ccE4fgHUvXmdOb+t4/jNXqIXpzbXZslexTD\n91EJua8Kc3Ro4iV1+F0I/zv4BfXnAX+OOBWw3+toAnA1vF+/DCafaa/sr9yvQIho\njXVqcerYnLK/0u0dNdU9JpvD0bNXTJmXbVJakNClW0i7k929PclqC7XaRb7C2WW9\nxwD4BH95gTN0pDI6f5XDf8XwTg3KI9K3Ni7m/VhYm3WMHOlFqpSXd5x/7bbD94SY\nF3qo3bYqxIrynALqeQ61ASsxusktLFxUw6MyMrptwfPRLCqhWzzxyQYR2PVekS5C\nQunI6GhF/7pQaPJmLYJIL9TRSTPCROodmrfumIvOdu958qmDpOOXg4bWp1OWszah\n7AAqy4O5/ef0yUR+yI39wV9dxabo8TWV1HyFCpDVXyr6oNTmheL30pX2WQx1qATG\ndshpFIAU4zflKMxc0tRk0c47rBmTMsocrveIk4HrQDUX8o3i0T4bwc0Y/tCrp9ze\nt/hFsGPRPncOWRy44xZ18OjRLWjNAgMBAAGjgakwgaYwCQYDVR0TBAIwADAsBglg\nhkgBhvhCAQ0EHxYdT3BlblNTTCBHZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0O\nBBYEFBNMl6pIuv5bcO0KXUXPoCEEuIKkMB8GA1UdIwQYMBaAFB9i8gxKs7VGd5QM\nlTBXkF3ffvLrMCsGA1UdEgQkMCKGIGh0dHA6Ly8xOTIuMTY4LjEwLjE4MC9zc2wv\nY2EuY3J0MA0GCSqGSIb3DQEBDQUAA4ICAQBVJC2IgPAzs/skjA0tRxPCDNuGln6c\naWf1YMaUyMRfrrmvVZRpcdPdfpL6aJfF8NSTlz1CzFOW41J2cPUBVEe38OVGJmqB\n00rpBUMUB6TRdiHDhiLVlfS/EkVRZomM/KxuxZyi13vjqQBUpcdvmqqeI5QxX3rG\n+29i/BzoW4aTg27d1SFLF1GG+9KuIShk05epSzZ2F+ndZHSwJ9lGYh0RQM00q2Wo\nrN/kGc0BOwJTdFM/gWtumEZgixLtkBSia5M0z/JiePR7C5gaYY2db1DXMLodzQoJ\nTRu0VA9ibN9SBCPg9P2peYzWyk8acdEVB+3AKBNFmoKiIaHh84U3JCh/u3lrEC06\nkdX9sKmIM4WJiXIFFlvS44peUmjpb0hZWlz/GA+2EeWNYm0dBHef50R2f6PPWuRv\nl1GyNne0Z7/RGQPcrI9TUEG0Dw6HQriSmTQWOaoAU8KlomDH+ChC5kbI/H4D3L2Y\nMyPa5iFuNe4RCPL7071B57r0q2WsIw8sHVX8zm04msbRZV/dPwZ/0mscMfdjdQzL\nnpdO7ZYj0dcwaZNFLbrFKmGOmFBTj6ygj4/b6Bd4U222mtMMR4u+Lck6quWCkHcC\ngoQW9TCAnIbu//URPCyA+pivyvwG+vy295xIAeaQYBtWWXOIKZttmbLBcmfx4KaD\nA9j3h4a3EzHoPQ==</ds:X509Certificate>\n</ds:X509Data>\n</ds:KeyInfo>\n</ds:Signature>\n    <ns0:NameIDPolicy AllowCreate=\"true\" Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\"/>\n     <ns0:RequestedAuthnContext Comparison=\"minimum\"><md1:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:SpidL1</md1:AuthnContextClassRef>    </ns0:RequestedAuthnContext>\n</ns0:AuthnRequest>",
    "provider": "infocrt"
  },
  "apiVersion": "1.1"
}');


--
-- TOC entry 2865 (class 0 OID 0)
-- Dependencies: 222
-- Name: respones_ID_seq; Type: SEQUENCE SET; Schema: log; Owner: easyspid
--

SELECT pg_catalog.setval('"respones_ID_seq"', 115, true);


--
-- TOC entry 2824 (class 0 OID 77258)
-- Dependencies: 223
-- Data for Name: responses; Type: TABLE DATA; Schema: log; Owner: easyspid
--

INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (14, 'b1d54fd3-b529-474b-98c9-e69850210936', '500', 'http://192.168.56.103:8888/api/prvd/uniroma1/consume', '2017-07-16 17:52:32.907652+02', '192.168.56.1', NULL);
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (15, '4aff4d18-81a8-4b2c-a015-19e504fb0eed', '500', 'http://192.168.56.103:8888/api/prvd/uniroma1/consume', '2017-07-16 17:55:13.181139+02', '192.168.56.1', NULL);
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (48, 'acaee9e4-0a84-4cee-87ed-5aa45b42132f', '500', 'http://192.168.56.103:8888/api/prvd/uniroma1/consume', '2017-07-17 00:05:19.74198+02', '192.168.56.1', '{"id": "0d2dd14d-511a-48cf-beef-2f01cbafd443", "error": {"code": "easyspid105", "message": "Db error", "httpcode": 500, "debugMessage": {"py/reduce": [{"py/type": "psycopg2.IntegrityError"}, ["duplicate key value violates unique constraint \"assertions_ID_assertion_key\"\nDETAIL:  Key (\"ID_assertion\")=(_d3bb9884-6657-48d1-9aa5-7b9d583bea77) already exists.\n"], {}, null, null]}}, "result": null, "apiVersion": "1.0"}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (49, '3850c130-19f6-4c16-ba05-efae28b11a57', '500', 'http://192.168.56.103:8888/api/prvd/uniroma1/consume', '2017-07-17 00:06:43.289508+02', '192.168.56.1', '{"id": "a097df0f-3053-4dd0-9732-ebee82bcae93", "error": {"code": "easyspid105", "message": "Db error", "httpcode": 500, "debugMessage": {"py/reduce": [{"py/type": "psycopg2.IntegrityError"}, ["duplicate key value violates unique constraint \"assertions_ID_assertion_key\"\nDETAIL:  Key (\"ID_assertion\")=(_d3bb9884-6657-48d1-9aa5-7b9d583bea77) already exists.\n"], {}, null, null]}}, "result": null, "apiVersion": "1.0"}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (50, '2597aaab-4127-4671-85fb-5530141aa18a', '500', 'http://192.168.56.103:8888/api/prvd/uniroma1/consume', '2017-07-17 00:07:58.354887+02', '192.168.56.1', '{"id": "67049ace-b292-446f-ae3d-93406b1f8610", "error": {"code": "easyspid105", "message": "Db error", "httpcode": 500, "debugMessage": {"py/reduce": [{"py/type": "psycopg2.IntegrityError"}, ["duplicate key value violates unique constraint \"assertions_ID_assertion_key\"\nDETAIL:  Key (\"ID_assertion\")=(_d3bb9884-6657-48d1-9aa5-7b9d583bea77) already exists.\n"], {}, null, null]}}, "result": null, "apiVersion": "1.0"}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (51, 'd9ea5cf9-923d-4b92-b37a-f79f03e140d4', '500', 'http://192.168.56.103:8888/api/prvd/uniroma1/consume', '2017-07-17 00:09:43.545449+02', '192.168.56.1', '{"id": "77a0c96e-88a8-4b36-a83a-a6a7e1948661", "error": {"code": "easyspid105", "message": "Db error", "httpcode": 500, "debugMessage": {"py/reduce": [{"py/type": "psycopg2.IntegrityError"}, ["duplicate key value violates unique constraint \"assertions_ID_assertion_key\"\nDETAIL:  Key (\"ID_assertion\")=(_d3bb9884-6657-48d1-9aa5-7b9d583bea77) already exists.\n"], {}, null, null]}}, "result": null, "apiVersion": "1.0"}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (52, '96e8e1e9-38ae-41c2-a8a9-d4b3d1135e67', '200', 'http://192.168.56.103:8888/api/prvd', '2017-07-17 00:11:58.195266+02', '192.168.56.1', '{"id": "78c2e984-f49f-42a7-ba65-9cabf0635270", "error": {"code": "200", "message": "OK", "httpcode": 200}, "result": {"providers": [{"code": "aruba", "name": "Aruba Pec S.p.A.", "type": "idp", "description": null}, {"code": "infocrt", "name": "Infocert S.p.A.", "type": "idp", "description": null}, {"code": "pt", "name": "Poste Italiane S.p.A.", "type": "idp", "description": null}, {"code": "uniroma1", "name": "Sapienza Università di Roma", "type": "sp", "description": null}, {"code": "sapienza", "name": "Sapienza Università di Roma", "type": "sp", "description": null}, {"code": "sielte", "name": "Sielte S.p.A.", "type": "idp", "description": null}, {"code": "titrusttech", "name": "TI Trust Technologies S.r.l.", "type": "idp", "description": null}]}, "apiVersion": "1.0"}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (53, 'c1abb558-91b9-4a19-bdc2-a5ff24683f63', '500', 'http://192.168.56.103:8888/api/prvd/uniroma1/consume', '2017-07-17 00:12:16.138157+02', '192.168.56.1', '{"id": "4bc9145f-bce7-4269-84f9-8adc3e351504", "error": {"code": "easyspid105", "message": "Db error", "httpcode": 500, "debugMessage": {"py/reduce": [{"py/type": "psycopg2.IntegrityError"}, ["duplicate key value violates unique constraint \"assertions_ID_assertion_key\"\nDETAIL:  Key (\"ID_assertion\")=(_d3bb9884-6657-48d1-9aa5-7b9d583bea77) already exists.\n"], {}, null, null]}}, "result": null, "apiVersion": "1.0"}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (54, '49a1b55f-e2d0-40d9-867e-5a5e7543a3ef', '500', 'http://192.168.56.103:8888/api/prvd/uniroma1/consume', '2017-07-17 00:13:49.173011+02', '192.168.56.1', '{"id": "60696d94-e636-4225-8e9e-aaeaccc464dd", "error": {"code": "500", "message": "Internal Server Error", "httpcode": 500}, "result": null, "apiVersion": "1.0"}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (55, '03f7caff-458e-4c3a-bc8c-89139df0dcf4', '500', 'http://192.168.56.103:8888/api/prvd/uniroma1/consume', '2017-07-17 00:15:32.123303+02', '192.168.56.1', '{
    "apiVersion": "1.0",
    "error": {
        "code": "500",
        "httpcode": 500,
        "message": "Internal Server Error"
    },
    "id": "a0fea976-2821-48b4-a31f-4e2b75892121",
    "result": null
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (56, 'fbb09aad-9120-45c8-a522-4bacd9a537b2', '401', 'http://192.168.56.103:8888/api/prvd/uniroma1/consume', '2017-07-17 00:29:20.077805+02', '192.168.56.1', '{
    "apiVersion": "1.0",
    "error": {
        "code": "easyspid110",
        "httpcode": 401,
        "message": "Saml Response does not match the ID of the AuthNRequest sent by the SP"
    },
    "id": "36e32ee6-0510-4a59-92f6-b7f049b995cc",
    "result": null
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (57, '1b8496cd-632b-431a-a7af-611628d8dc35', '200', 'http://192.168.56.103:8888/api/prvd/uniroma1/authnreq/login?idp=pt&attrindex=0&binding=post&srelay=uniroma1_srelay1', '2017-07-17 00:36:12.612059+02', '192.168.56.1', '{
    "apiVersion": "1.0",
    "error": {
        "code": "200",
        "httpcode": 200,
        "message": "OK"
    },
    "id": "42e59b2d-27fe-4788-8d80-8e16e8930b3a",
    "result": {
        "jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDAyNDU3NzIsImlhdCI6MTUwMDI0NDU3MiwiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6IjQzMDM4YWI2LTBiODQtNDliNS04NTBlLTJhNGQ3ZmZkZmU4ZiIsIm5iZiI6MTUwMDI0NDU3Miwic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.UQg3lRBbiHu1OU_sI-3FTIozfe1SFxM5dc4QeIuD38g",
        "postTo": "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\"><html>    <head>        <meta http-equiv=''Content-Type'' content=''text/html; charset=utf-8''>        <meta http-equiv=''Cache-Control'' content=''no-cache, no-store'' >        <meta http-equiv=''Pragma'' content=''no-cache'' >    </head>    <body onLoad=\"javascript:document.SPIDForm.submit()\">        <form action=\"https://posteid.poste.it/jod-fs/ssoservicepost\"  method=''POST'' name=''SPIDForm''>            <input type=''hidden'' name=''SAMLRequest'' value=\"PG5zMDpBdXRoblJlcXVlc3QgeG1sbnM6bWQxPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiB4bWxuczpuczA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCIgQXNzZXJ0aW9uQ29uc3VtZXJTZXJ2aWNlVVJMPSJodHRwOi8vd3d3LnVuaXJvbWExLml0L3NwaWQvY29uc3VtZSIgQXR0cmlidXRlQ29uc3VtaW5nU2VydmljZUluZGV4PSIwIiBEZXN0aW5hdGlvbj0iaHR0cHM6Ly9wb3N0ZWlkLnBvc3RlLml0L2pvZC1mcy9zc29zZXJ2aWNlcmVkaXJlY3QiIEZvcmNlQXV0aG49InRydWUiIElEPSJPTkVMT0dJTl9lZTM5ODIyODgwOTY0NTRhMTIzNzM5ZTU0MzYyNzMwNjQzNmRiNWNhIiBJc3N1ZUluc3RhbnQ9IjIwMTctMDctMTZUMjI6MzY6MTJaIiBQcm90b2NvbEJpbmRpbmc9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpiaW5kaW5nczpIVFRQLVBPU1QiIFByb3ZpZGVyTmFtZT0iVW5pdmVyc2l0JiMyMjQ7IGRlZ2xpIFN0dWRpIExhIFNhcGllbnphIC0gUm9tYSIgVmVyc2lvbj0iMi4wIj4KICAgIDxtZDE6SXNzdWVyIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6ZW50aXR5IiBOYW1lUXVhbGlmaWVyPSJodHRwOi8vd3d3LnVuaXJvbWExLml0Ij5odHRwOi8vd3d3LnVuaXJvbWExLml0PC9tZDE6SXNzdWVyPjxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPgo8ZHM6U2lnbmVkSW5mbz4KPGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz4KPGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZHNpZy1tb3JlI3JzYS1zaGEyNTYiLz4KPGRzOlJlZmVyZW5jZSBVUkk9IiNPTkVMT0dJTl9lZTM5ODIyODgwOTY0NTRhMTIzNzM5ZTU0MzYyNzMwNjQzNmRiNWNhIj4KPGRzOlRyYW5zZm9ybXM+CjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPgo8ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+CjwvZHM6VHJhbnNmb3Jtcz4KPGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiIvPgo8ZHM6RGlnZXN0VmFsdWU+VEYxVHYyU2ZWd0pranFiNGVqVkNWTTY2L0RLSGpMd0lQcDFDNDk2SDZ6TT08L2RzOkRpZ2VzdFZhbHVlPgo8L2RzOlJlZmVyZW5jZT4KPC9kczpTaWduZWRJbmZvPgo8ZHM6U2lnbmF0dXJlVmFsdWU+VlZsSnJSTjJwcEJkVG9NaFlmdzY1ODFWNzNSOERJRm9mYi96eW1RZXZXcDU4Q0NJdGdjVm4yWUc3MHR5ZGxLRQpKc05WSHRhWWhoVGZpZGcwMXh0OVk2UHFkZkFYbEowNlZCUG43ME9idStmQ2FiQzBnQmlIbXNVdDc0YUxQQ1ZCCjVMdEEvbWJUT3A1czJjcVVNUDB1SXd2K3JtbHhzL0ZqSEpRWnJsT0Q3citDaG55YlBoeEM5dWtYU0lnc0xST0wKVThGeUNwNTRQeDF4djdsT1Uyd1ljT1ZkclBVRHJwcmdac3MzOFJSL1Y5bmlENmd0T2phbzJuamo2eVZ1V2lnZgpOSDhyTWdlaXVZenVQRmREUllRTUNHcHl1UzJWcEc1WWo4N1p5L3VRL1VlSFVSaWxmZlFPMzNYRGVCbXpxNk90CjNQeGhSOU4zZDdWaWRhQzU0dEtjbVE9PTwvZHM6U2lnbmF0dXJlVmFsdWU+CjxkczpLZXlJbmZvPgo8ZHM6WDUwOURhdGE+CjxkczpYNTA5Q2VydGlmaWNhdGU+TUlJRWZqQ0NBMmFnQXdJQkFnSVJBTEtYalVITXZtZTBBZ0R3M0ZGRjYzMHdEUVlKS29aSWh2Y05BUUVGQlFBdwpOakVMTUFrR0ExVUVCaE1DVGt3eER6QU5CZ05WQkFvVEJsUkZVa1ZPUVRFV01CUUdBMVVFQXhNTlZFVlNSVTVCCklGTlRUQ0JEUVRBZUZ3MHhOREEzTVRZd01EQXdNREJhRncweE56QTNNVFV5TXpVNU5UbGFNRVl4SVRBZkJnTlYKQkFzVEdFUnZiV0ZwYmlCRGIyNTBjbTlzSUZaaGJHbGtZWFJsWkRFaE1COEdBMVVFQXhNWWQzZDNMbk4wZFdSbApiblJwTG5WdWFYSnZiV0V4TG1sME1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBCm5EekhKYlRpUGJ4MVpLWGJVeGZFYUdSVnpLaVZHNVZ0dHFXaXk5RENyT0wwblpCOVZCRnV6ODF2WHdlditYUEYKUEl3WEFHei9UMHVwZjl0NG02ejVpdkdRdDRpSlNKUVZHMmd5cXZ0N3NKZ3l3M2VQMmF4SzN2UVQwbUR0eFN2UgpqbzhITTdlUUhqd0dUUEY0NVdLejhVTHg5cXZSQUk2Nk1uOHVCaHF1SC91Q0djbWdCZTB0NkZQQWQ2ck4xRk1iCkY1R2tFaEVabi9Oa1UzZlZ1TVJndGFqUmdUNGYxbXhvdUxIQnJVODcySEJsYU12UzFmaElKMi90Z2EvSGg5OGIKMlREVlA3bjBsVVR6V2h4S1VBZEN5eEVFdzNPeWh3azZkWVNvN1J0WmlPWndDam4vZkZiazVXN3RxS01lVmk4dgp4NE9YUTdwbjJPcnpBamhUVzVxRU1RSURBUUFCbzRJQmRUQ0NBWEV3SHdZRFZSMGpCQmd3Rm9BVURMMlRhQXp6CjNxdWpTV3NyTjFkSDZwRGp1ZTB3SFFZRFZSME9CQllFRkg4YVB3U3lDUU1YeFMwalB6MStIcHRqdklTM01BNEcKQTFVZER3RUIvd1FFQXdJRm9EQU1CZ05WSFJNQkFmOEVBakFBTUIwR0ExVWRKUVFXTUJRR0NDc0dBUVVGQndNQgpCZ2dyQmdFRkJRY0RBakFpQmdOVkhTQUVHekFaTUEwR0N5c0dBUVFCc2pFQkFnSWRNQWdHQm1lQkRBRUNBVEE2CkJnTlZIUjhFTXpBeE1DK2dMYUFyaGlsb2RIUndPaTh2WTNKc0xuUmpjeTUwWlhKbGJtRXViM0puTDFSRlVrVk8KUVZOVFRFTkJMbU55YkRCdEJnZ3JCZ0VGQlFjQkFRUmhNRjh3TlFZSUt3WUJCUVVITUFLR0tXaDBkSEE2THk5agpjblF1ZEdOekxuUmxjbVZ1WVM1dmNtY3ZWRVZTUlU1QlUxTk1RMEV1WTNKME1DWUdDQ3NHQVFVRkJ6QUJoaHBvCmRIUndPaTh2YjJOemNDNTBZM011ZEdWeVpXNWhMbTl5WnpBakJnTlZIUkVFSERBYWdoaDNkM2N1YzNSMVpHVnUKZEdrdWRXNXBjbTl0WVRFdWFYUXdEUVlKS29aSWh2Y05BUUVGQlFBRGdnRUJBR0tpZmNyVW5xSXFZaEU0Um5FRAptT1JLRC9CMEZLNmVQSXo2ZGRMYVE1Y3VNTmlZUFVLM041Z3dIS3N0TkpKQUR4bGdNWmNRQ05scXRjb1dSejh5ClZJVzkrSHZXZERWMHJnNDZ4YjBmWGdjRUFQOXFlZzlCOCtBWGFSV3c0emczNTVST1ZMVUIyd3hVNXhPbEVHN0sKMWRVQjVJVnRKbEdxK1lMb2J5R2ZUb2dLWDg1YWhTTFdkUEtmZVp3RlVxaGJTYWFEdnJZVHlrK2Q0bDUyc291bAp3TU4vSFdMRklxelBqWkliVHdvcGgrQmUrVDNoSVVRRlJEZzN3RkFiSEN4UVkveUtRSllCeHNKT0M0U2ZxNWZhCmdINHdvbGRQeEhMaUErRFhvSEdtSDJUNE5pMy9Qdmp3aklEamk3K01mZFcxbG9XMmJlWWZGZFZETUdhQ1lTdE8KK3hjPTwvZHM6WDUwOUNlcnRpZmljYXRlPgo8L2RzOlg1MDlEYXRhPgo8L2RzOktleUluZm8+CjwvZHM6U2lnbmF0dXJlPgogICAgPG5zMDpOYW1lSURQb2xpY3kgQWxsb3dDcmVhdGU9InRydWUiIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6dHJhbnNpZW50Ii8+CiAgICAgPG5zMDpSZXF1ZXN0ZWRBdXRobkNvbnRleHQgQ29tcGFyaXNvbj0ibWluaW11bSI+PG1kMTpBdXRobkNvbnRleHRDbGFzc1JlZj51cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YWM6Y2xhc3NlczpTcGlkTDE8L21kMTpBdXRobkNvbnRleHRDbGFzc1JlZj4gICAgPC9uczA6UmVxdWVzdGVkQXV0aG5Db250ZXh0Pgo8L25zMDpBdXRoblJlcXVlc3Q+\" />            <input type=''hidden'' name=''RelayState'' value=\"dW5pcm9tYTFfc3JlbGF5MQ==\" />            <noscript>                <h2 style=''color:0000FF''>Sapienza \"SPID - Gateway\"</h2>                <h3 style=''color: red;''>Javascript disabilitato</h3>                <input type=''submit'' value=''Invia Autorizzazione di Autenticazione'' />            </noscript>        </form>    </body></html>"
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (58, '74bc87c0-bb99-4190-87fc-6c254e131dce', '200', 'http://192.168.56.103:8888/api/jwt/getByType?type=jwt1', '2017-07-17 00:46:03.915304+02', '192.168.56.1', '{"id": "3124bae4-2c8f-4e10-8fe3-8239d45455ff", "error": {"code": "200", "message": "OK", "httpcode": 200}, "result": {"token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDAyNDYzNjMsImlhdCI6MTUwMDI0NTE2MywiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6IjM3NjUzNWZiLTgyNjYtNDkxMi1iZTBmLTAzYTUwNzE0YjM4ZCIsIm5iZiI6MTUwMDI0NTE2Mywic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.gYPCMkuB2_xJ0KUKqyRFyoBPVPGmJ7ZIgtrA918WqOs"}, "apiVersion": "1.0"}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (59, 'e7a29c8d-b6ec-470f-991a-f7a9d4bb5d80', '404', 'http://192.168.56.103:8888/api/prvd/uniroma1/consume', '2017-07-17 17:48:40.39166+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "easyspid101",
        "httpcode": 404,
        "message": "Sp not found"
    },
    "id": "5f7efada-d9d7-4049-b45c-cd13974f1d11",
    "result": null
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (60, 'ff5ac684-ff58-48f7-a04f-72ea9f8eed5d', '200', 'http://192.168.56.103:8888/api/prvd/pt/metadata', '2017-07-24 07:11:39.972529+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "200",
        "httpcode": 200,
        "message": "OK"
    },
    "id": "45ae7e5a-bea8-481f-9b15-661d74f2e16e",
    "result": {
        "fingerPrintAlg": "sha1",
        "key": null,
        "metadata": "<?xml version=\"1.0\" standalone=\"no\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"_5145ad9c-675b-4277-84f6-324773418d64\" cacheDuration=\"P0Y0M30DT0H0M0.000S\" entityID=\"https://posteid.poste.it\"><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"#_5145ad9c-675b-4277-84f6-324773418d64\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>XiFV1ppZSffZg49dIHdB9cHMm9d7Tob66Bk4eRcX+E8=</DigestValue></Reference></SignedInfo><SignatureValue>xnJ5evn7Iv8tOciW6TGwyl/XqS59UJzGfQqGSMURyw6h5qVnHFsDz8yiqz2jI/TANHP6sCB2f0ix\rbfkU/8PtW7ZOVL58IMpsLvaLyuYQLImWxh2Z3giUIx8veSAI6pTMEplhQlDTYsF25bPV/TTOblYe\rzNlJvZ31lKOMNWMS0ruNfjv+IUTLPT95Ibi3f8pZpLNh7BU5ytF48fbrIJHMLA7U0LGFPURsfeaF\ri4PmqGAidqOktN4HI2QxcFQUV8rBvRbibHgW2VOxEkLs6rQfkrla8NAMalauNCThCcGtZQ3vjchz\rOzxtZC6Ot57nadJ/qpOMboAjwSMBho5jwDgriA==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIEKzCCAxOgAwIBAgIDE2Y0MA0GCSqGSIb3DQEBCwUAMGAxCzAJBgNVBAYTAklUMRgwFgYDVQQK\rDA9Qb3N0ZWNvbSBTLnAuQS4xIDAeBgNVBAsMF0NlcnRpZmljYXRpb24gQXV0aG9yaXR5MRUwEwYD\rVQQDDAxQb3N0ZWNvbSBDQTMwHhcNMTYwMjI2MTU1MjQ0WhcNMjEwMjI2MTU1MjQ0WjBxMQswCQYD\rVQQGEwJJVDEOMAwGA1UECAwFSXRhbHkxDTALBgNVBAcMBFJvbWUxHjAcBgNVBAoMFVBvc3RlIEl0\rYWxpYW5lIFMucC5BLjENMAsGA1UECwwEU1BJRDEUMBIGA1UEAwwLSURQLVBvc3RlSUQwggEiMA0G\rCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDZFEtJoEHFAjpCaZcj5DVWrRDyaLZyu31XApslbo87\rCyWz61OJMtw6QQU0MdCtrYbtSJ6vJwx7/6EUjsZ3u4x3EPLdlkyiGOqukPwATv4c7TVOUVs5onIq\rTphM9b+AHRg4ehiMGesm/9d7RIaLuN79iPUvdLn6WP3idAfEw+rhJ/wYEQ0h1Xm5osNUgtWcBGav\rZIjLssWNrDDfJYxXH3QZ0kI6feEvLCJwgjXLGkBuhFehNhM4fhbX9iUCWwwkJ3JsP2++Rc/iTA0L\rZhiUsXNNq7gBcLAJ9UX2V1dWjTzBHevfHspzt4e0VgIIwbDRqsRtF8VUPSDYYbLoqwbLt18XAgMB\rAAGjgdwwgdkwRgYDVR0gBD8wPTAwBgcrTAsBAgEBMCUwIwYIKwYBBQUHAgEWF2h0dHA6Ly93d3cu\rcG9zdGVjZXJ0Lml0MAkGBytMCwEBCgIwDgYDVR0PAQH/BAQDAgSwMB8GA1UdIwQYMBaAFKc0XP2F\rByYU2l0gFzGKE8zVSzfmMD8GA1UdHwQ4MDYwNKAyoDCGLmh0dHA6Ly9wb3N0ZWNlcnQucG9zdGUu\raXQvcG9zdGVjb21jYTMvY3JsMy5jcmwwHQYDVR0OBBYEFEvrikZQkfBjuiTpxExSBe8wGgsyMA0G\rCSqGSIb3DQEBCwUAA4IBAQBNAw8UoeiCF+1rFs27d3bEef6CLe/PJga9EfwKItjMDD9QzT/FShRW\rKLHlK69MHL1ZLPRPvuWUTkIOHTpNqBPILvO1u13bSg+6o+2OdqAkCBkbTqbGjWSPLaTUVNV6MbXm\rvttD8Vd9vIZg1xBBG3Fai13dwvSj3hAZd8ug8a8fW1y/iDbRC5D1O+HlHDuvIW4LbJ093jdj+oZw\rSyd216gtXL00QA0C1uMuDv9Wf9IxniTb710dRSgIcM4/eR7832fZgdOsoalFzGYWxSCs8WOZrjpu\rb1fdaRSEuCQk2+gmdsiRcTs9EqPCCNiNlrNAiWEyGtL8A4ao3pDMwCtrb2yr</X509Certificate></X509Data></KeyInfo></Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIIEKzCCAxOgAwIBAgIDE2Y0MA0GCSqGSIb3DQEBCwUAMGAxCzAJBgNVBAYTAklUMRgwFgYDVQQK\rDA9Qb3N0ZWNvbSBTLnAuQS4xIDAeBgNVBAsMF0NlcnRpZmljYXRpb24gQXV0aG9yaXR5MRUwEwYD\rVQQDDAxQb3N0ZWNvbSBDQTMwHhcNMTYwMjI2MTU1MjQ0WhcNMjEwMjI2MTU1MjQ0WjBxMQswCQYD\rVQQGEwJJVDEOMAwGA1UECAwFSXRhbHkxDTALBgNVBAcMBFJvbWUxHjAcBgNVBAoMFVBvc3RlIEl0\rYWxpYW5lIFMucC5BLjENMAsGA1UECwwEU1BJRDEUMBIGA1UEAwwLSURQLVBvc3RlSUQwggEiMA0G\rCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDZFEtJoEHFAjpCaZcj5DVWrRDyaLZyu31XApslbo87\rCyWz61OJMtw6QQU0MdCtrYbtSJ6vJwx7/6EUjsZ3u4x3EPLdlkyiGOqukPwATv4c7TVOUVs5onIq\rTphM9b+AHRg4ehiMGesm/9d7RIaLuN79iPUvdLn6WP3idAfEw+rhJ/wYEQ0h1Xm5osNUgtWcBGav\rZIjLssWNrDDfJYxXH3QZ0kI6feEvLCJwgjXLGkBuhFehNhM4fhbX9iUCWwwkJ3JsP2++Rc/iTA0L\rZhiUsXNNq7gBcLAJ9UX2V1dWjTzBHevfHspzt4e0VgIIwbDRqsRtF8VUPSDYYbLoqwbLt18XAgMB\rAAGjgdwwgdkwRgYDVR0gBD8wPTAwBgcrTAsBAgEBMCUwIwYIKwYBBQUHAgEWF2h0dHA6Ly93d3cu\rcG9zdGVjZXJ0Lml0MAkGBytMCwEBCgIwDgYDVR0PAQH/BAQDAgSwMB8GA1UdIwQYMBaAFKc0XP2F\rByYU2l0gFzGKE8zVSzfmMD8GA1UdHwQ4MDYwNKAyoDCGLmh0dHA6Ly9wb3N0ZWNlcnQucG9zdGUu\raXQvcG9zdGVjb21jYTMvY3JsMy5jcmwwHQYDVR0OBBYEFEvrikZQkfBjuiTpxExSBe8wGgsyMA0G\rCSqGSIb3DQEBCwUAA4IBAQBNAw8UoeiCF+1rFs27d3bEef6CLe/PJga9EfwKItjMDD9QzT/FShRW\rKLHlK69MHL1ZLPRPvuWUTkIOHTpNqBPILvO1u13bSg+6o+2OdqAkCBkbTqbGjWSPLaTUVNV6MbXm\rvttD8Vd9vIZg1xBBG3Fai13dwvSj3hAZd8ug8a8fW1y/iDbRC5D1O+HlHDuvIW4LbJ093jdj+oZw\rSyd216gtXL00QA0C1uMuDv9Wf9IxniTb710dRSgIcM4/eR7832fZgdOsoalFzGYWxSCs8WOZrjpu\rb1fdaRSEuCQk2+gmdsiRcTs9EqPCCNiNlrNAiWEyGtL8A4ao3pDMwCtrb2yr</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://posteid.poste.it/jod-fs/sloservicepost\" ResponseLocation=\"https://posteid.poste.it/jod-fs/sloserviceresponsepost\"/><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://posteid.poste.it/jod-fs/sloserviceredirect\" ResponseLocation=\"https://posteid.poste.it/jod-fs/sloserviceresponseredirect\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://posteid.poste.it/jod-fs/ssoservicepost\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://posteid.poste.it/jod-fs/ssoserviceredirect\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"familyName\" NameFormat=\"xsi:string\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"name\" NameFormat=\"xsi:string\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"spidCode\" NameFormat=\"xsi:string\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"fiscalNumber\" NameFormat=\"xsi:string\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"gender\" NameFormat=\"xsi:string\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"dateOfBirth\" NameFormat=\"xsi:string\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"placeOfBirth\" NameFormat=\"xsi:string\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"countyOfBirth\" NameFormat=\"xsi:string\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"idCard\" NameFormat=\"xsi:string\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"address\" NameFormat=\"xsi:string\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"digitalAddress\" NameFormat=\"xsi:string\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"expirationDate\" NameFormat=\"xsi:string\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"email\" NameFormat=\"xsi:string\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"mobilePhone\" NameFormat=\"xsi:string\"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang=\"it\">Poste Italiane SpA</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"it\">Poste Italiane SpA</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"it\">https://www.poste.it</md:OrganizationURL></md:Organization></md:EntityDescriptor>",
        "x509cert": "-----BEGIN CERTIFICATE-----\nMIIEKzCCAxOgAwIBAgIDE2Y0MA0GCSqGSIb3DQEBCwUAMGAxCzAJBgNVBAYTAklUMRgwFgYDVQQK\nDA9Qb3N0ZWNvbSBTLnAuQS4xIDAeBgNVBAsMF0NlcnRpZmljYXRpb24gQXV0aG9yaXR5MRUwEwYD\nVQQDDAxQb3N0ZWNvbSBDQTMwHhcNMTYwMjI2MTU1MjQ0WhcNMjEwMjI2MTU1MjQ0WjBxMQswCQYD\nVQQGEwJJVDEOMAwGA1UECAwFSXRhbHkxDTALBgNVBAcMBFJvbWUxHjAcBgNVBAoMFVBvc3RlIEl0\nYWxpYW5lIFMucC5BLjENMAsGA1UECwwEU1BJRDEUMBIGA1UEAwwLSURQLVBvc3RlSUQwggEiMA0G\nCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDZFEtJoEHFAjpCaZcj5DVWrRDyaLZyu31XApslbo87\nCyWz61OJMtw6QQU0MdCtrYbtSJ6vJwx7/6EUjsZ3u4x3EPLdlkyiGOqukPwATv4c7TVOUVs5onIq\nTphM9b+AHRg4ehiMGesm/9d7RIaLuN79iPUvdLn6WP3idAfEw+rhJ/wYEQ0h1Xm5osNUgtWcBGav\nZIjLssWNrDDfJYxXH3QZ0kI6feEvLCJwgjXLGkBuhFehNhM4fhbX9iUCWwwkJ3JsP2++Rc/iTA0L\nZhiUsXNNq7gBcLAJ9UX2V1dWjTzBHevfHspzt4e0VgIIwbDRqsRtF8VUPSDYYbLoqwbLt18XAgMB\nAAGjgdwwgdkwRgYDVR0gBD8wPTAwBgcrTAsBAgEBMCUwIwYIKwYBBQUHAgEWF2h0dHA6Ly93d3cu\ncG9zdGVjZXJ0Lml0MAkGBytMCwEBCgIwDgYDVR0PAQH/BAQDAgSwMB8GA1UdIwQYMBaAFKc0XP2F\nByYU2l0gFzGKE8zVSzfmMD8GA1UdHwQ4MDYwNKAyoDCGLmh0dHA6Ly9wb3N0ZWNlcnQucG9zdGUu\naXQvcG9zdGVjb21jYTMvY3JsMy5jcmwwHQYDVR0OBBYEFEvrikZQkfBjuiTpxExSBe8wGgsyMA0G\nCSqGSIb3DQEBCwUAA4IBAQBNAw8UoeiCF+1rFs27d3bEef6CLe/PJga9EfwKItjMDD9QzT/FShRW\nKLHlK69MHL1ZLPRPvuWUTkIOHTpNqBPILvO1u13bSg+6o+2OdqAkCBkbTqbGjWSPLaTUVNV6MbXm\nvttD8Vd9vIZg1xBBG3Fai13dwvSj3hAZd8ug8a8fW1y/iDbRC5D1O+HlHDuvIW4LbJ093jdj+oZw\nSyd216gtXL00QA0C1uMuDv9Wf9IxniTb710dRSgIcM4/eR7832fZgdOsoalFzGYWxSCs8WOZrjpu\nb1fdaRSEuCQk2+gmdsiRcTs9EqPCCNiNlrNAiWEyGtL8A4ao3pDMwCtrb2yr\n-----END CERTIFICATE-----",
        "x509certFingerPrint": "ab1bf09a9bcaeb1e8a243bc7f98de4325c066754"
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (61, '023f14b2-157f-41a8-9215-12c17f7d122a', '200', 'http://192.168.56.103:8888/api/prvd/aruba/metadata', '2017-07-24 07:13:18.34153+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "200",
        "httpcode": 200,
        "message": "OK"
    },
    "id": "c15f0651-24a1-4ba8-84b1-0e617e9b3b26",
    "result": {
        "fingerPrintAlg": "sha1",
        "key": null,
        "metadata": "\r<md:EntityDescriptor ID=\"_76b0b4bb-956e-4c40-b493-281cbed5b7f3\" entityID=\"https://loginspid.aruba.it\" xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\"><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><ds:Reference URI=\"#_76b0b4bb-956e-4c40-b493-281cbed5b7f3\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>ZrvubwZHMwi2OESXVBWa1RMz9M0S4WK9CylEPhPeZXs=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>iGhOzmnfTGowXk99BH9MekN742hx38dUorFQFkGyZuvhqjLWaSdxz5zYULDH59FdBY1FvjZFoLZmSTBVU+uT6hzyXAMRcaLp0eGoGXjOIG2viU0YBnnIlaHdzY8H0hs2IepAcH0z0/d78bPBASZJezzjONUjpfsUSYRLQ46Tg6PANWTVkSZprGsaDLOvEPYcgjQsiLahVucloGKXrlfttwrl23xGQZQ1umgF+zIi7291JcOcXVYbDMzeWXhsbmzZo9EGUWVaqbsnvNje3nMwF4x7C9z6NnrbpPIulgG2ZAAnvxRw593okL7w2mTsmisqFN5HUTgs9SVFBrHTp1ygxA==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIExTCCA62gAwIBAgIQIHtEvEhGM77HwqsuvSbi9zANBgkqhkiG9w0BAQsFADBsMQswCQYDVQQG\rEwJJVDEYMBYGA1UECgwPQXJ1YmFQRUMgUy5wLkEuMSEwHwYDVQQLDBhDZXJ0aWZpY2F0aW9uIEF1\rdGhvcml0eUIxIDAeBgNVBAMMF0FydWJhUEVDIFMucC5BLiBORyBDQSAyMB4XDTE3MDEyMzAwMDAw\rMFoXDTIwMDEyMzIzNTk1OVowgaAxCzAJBgNVBAYTAklUMRYwFAYDVQQKDA1BcnViYSBQRUMgc3Bh\rMREwDwYDVQQLDAhQcm9kb3R0bzEWMBQGA1UEAwwNcGVjLml0IHBlYy5pdDEZMBcGA1UEBRMQWFhY\rWFhYMDBYMDBYMDAwWDEPMA0GA1UEKgwGcGVjLml0MQ8wDQYDVQQEDAZwZWMuaXQxETAPBgNVBC4T\rCDE2MzQ1MzgzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqt2oHJhcp03l73p+QYpE\rJ+f3jYYj0W0gos0RItZx/w4vpsiKBygaqDNVWSwfo1aPdVDIX13f62O+lBki29KTt+QWv5K6SGHD\rUXYPntRdEQlicIBh2Z0HfrM7fDl+xeJrMp1s4dsSQAuB5TJOlFZq7xCQuukytGWBTvjfcN/os5aE\rsEg+RbtZHJR26SbbUcIqWb27Swgj/9jwK+tvzLnP4w8FNvEOrNfR0XwTMNDFrwbOCuWgthv5jNBs\rVZaoqNwiA/MxYt+gTOMj/o5PWKk8Wpm6o/7/+lWAoxh0v8x9OkbIi+YaFpIxuCcUqsrJJk63x2gH\rCc2nr+yclYUhsKD/AwIDAQABo4IBLDCCASgwDgYDVR0PAQH/BAQDAgeAMB0GA1UdDgQWBBTKQ3+N\rPGcXFk8nX994vMTVpba1EzBHBgNVHSAEQDA+MDwGCysGAQQBgegtAQEBMC0wKwYIKwYBBQUHAgEW\rH2h0dHBzOi8vY2EuYXJ1YmFwZWMuaXQvY3BzLmh0bWwwWAYDVR0fBFEwTzBNoEugSYZHaHR0cDov\rL2NybC5hcnViYXBlYy5pdC9BcnViYVBFQ1NwQUNlcnRpZmljYXRpb25BdXRob3JpdHlCL0xhdGVz\rdENSTC5jcmwwHwYDVR0jBBgwFoAU8v9jQBwRQv3M3/FZ9m7omYcxR3kwMwYIKwYBBQUHAQEEJzAl\rMCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5hcnViYXBlYy5pdDANBgkqhkiG9w0BAQsFAAOCAQEA\rnEw0NuaspbpDjA5wggwFtfQydU6b3Bw2/KXPRKS2JoqGmx0SYKj+L17A2KUBa2c7gDtKXYz0FLT6\r0Bv0pmBN/oYCgVMEBJKqwRwdki9YjEBwyCZwNEx1kDAyyqFEVU9vw/OQfrAdp7MTbuZGFKknVt7b\r9wOYy/Op9FiUaTg6SuOy0ep+rqhihltYNAAl4L6fY45mHvqa5vvVG30OvLW/S4uvRYUXYwY6KhWv\rNdDf5CnFugnuEZtHJrVe4wx9aO5GvFLFZ/mQ35C5mXPQ7nIb0CDdLBJdz82nUoLSA5BUbeXAUkfa\rhW/hLxLdhks68/TK694xVIuiB40pvMmJwxIyDA==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIIExTCCA62gAwIBAgIQIHtEvEhGM77HwqsuvSbi9zANBgkqhkiG9w0BAQsFADBsMQswCQYDVQQG\rEwJJVDEYMBYGA1UECgwPQXJ1YmFQRUMgUy5wLkEuMSEwHwYDVQQLDBhDZXJ0aWZpY2F0aW9uIEF1\rdGhvcml0eUIxIDAeBgNVBAMMF0FydWJhUEVDIFMucC5BLiBORyBDQSAyMB4XDTE3MDEyMzAwMDAw\rMFoXDTIwMDEyMzIzNTk1OVowgaAxCzAJBgNVBAYTAklUMRYwFAYDVQQKDA1BcnViYSBQRUMgc3Bh\rMREwDwYDVQQLDAhQcm9kb3R0bzEWMBQGA1UEAwwNcGVjLml0IHBlYy5pdDEZMBcGA1UEBRMQWFhY\rWFhYMDBYMDBYMDAwWDEPMA0GA1UEKgwGcGVjLml0MQ8wDQYDVQQEDAZwZWMuaXQxETAPBgNVBC4T\rCDE2MzQ1MzgzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqt2oHJhcp03l73p+QYpE\rJ+f3jYYj0W0gos0RItZx/w4vpsiKBygaqDNVWSwfo1aPdVDIX13f62O+lBki29KTt+QWv5K6SGHD\rUXYPntRdEQlicIBh2Z0HfrM7fDl+xeJrMp1s4dsSQAuB5TJOlFZq7xCQuukytGWBTvjfcN/os5aE\rsEg+RbtZHJR26SbbUcIqWb27Swgj/9jwK+tvzLnP4w8FNvEOrNfR0XwTMNDFrwbOCuWgthv5jNBs\rVZaoqNwiA/MxYt+gTOMj/o5PWKk8Wpm6o/7/+lWAoxh0v8x9OkbIi+YaFpIxuCcUqsrJJk63x2gH\rCc2nr+yclYUhsKD/AwIDAQABo4IBLDCCASgwDgYDVR0PAQH/BAQDAgeAMB0GA1UdDgQWBBTKQ3+N\rPGcXFk8nX994vMTVpba1EzBHBgNVHSAEQDA+MDwGCysGAQQBgegtAQEBMC0wKwYIKwYBBQUHAgEW\rH2h0dHBzOi8vY2EuYXJ1YmFwZWMuaXQvY3BzLmh0bWwwWAYDVR0fBFEwTzBNoEugSYZHaHR0cDov\rL2NybC5hcnViYXBlYy5pdC9BcnViYVBFQ1NwQUNlcnRpZmljYXRpb25BdXRob3JpdHlCL0xhdGVz\rdENSTC5jcmwwHwYDVR0jBBgwFoAU8v9jQBwRQv3M3/FZ9m7omYcxR3kwMwYIKwYBBQUHAQEEJzAl\rMCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5hcnViYXBlYy5pdDANBgkqhkiG9w0BAQsFAAOCAQEA\rnEw0NuaspbpDjA5wggwFtfQydU6b3Bw2/KXPRKS2JoqGmx0SYKj+L17A2KUBa2c7gDtKXYz0FLT6\r0Bv0pmBN/oYCgVMEBJKqwRwdki9YjEBwyCZwNEx1kDAyyqFEVU9vw/OQfrAdp7MTbuZGFKknVt7b\r9wOYy/Op9FiUaTg6SuOy0ep+rqhihltYNAAl4L6fY45mHvqa5vvVG30OvLW/S4uvRYUXYwY6KhWv\rNdDf5CnFugnuEZtHJrVe4wx9aO5GvFLFZ/mQ35C5mXPQ7nIb0CDdLBJdz82nUoLSA5BUbeXAUkfa\rhW/hLxLdhks68/TK694xVIuiB40pvMmJwxIyDA==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://loginspid.aruba.it/ServiceLogoutRequest\"/><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://loginspid.aruba.it/ServiceLogoutRequest\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://loginspid.aruba.it/ServiceLoginWelcome\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://loginspid.aruba.it/ServiceLoginWelcome\"/><saml2:Attribute FriendlyName=\"Codice identificativo SPID\" Name=\"spidCode\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/><saml2:Attribute FriendlyName=\"Nome\" Name=\"name\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/><saml2:Attribute FriendlyName=\"Cognome\" Name=\"familyName\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/><saml2:Attribute FriendlyName=\"Luogo di nascita\" Name=\"placeOfBirth\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/><saml2:Attribute FriendlyName=\"Provincia di nascita\" Name=\"countyOfBirth\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/><saml2:Attribute FriendlyName=\"Data di nascita\" Name=\"dateOfBirth\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/><saml2:Attribute FriendlyName=\"Sesso\" Name=\"gender\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/><saml2:Attribute FriendlyName=\"Ragione o denominazione sociale\" Name=\"companyName\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/><saml2:Attribute FriendlyName=\"Sede legale\" Name=\"registeredOffice\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/><saml2:Attribute FriendlyName=\"Codice fiscale\" Name=\"fiscalNumber\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/><saml2:Attribute FriendlyName=\"Partita IVA\" Name=\"ivaCode\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/><saml2:Attribute FriendlyName=\"Documento d''identit\u00c3\u00a0\" Name=\"idCard\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/><saml2:Attribute FriendlyName=\"Numero di telefono mobile\" Name=\"mobilePhone\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/><saml2:Attribute FriendlyName=\"Indirizzo di posta elettronica\" Name=\"email\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/><saml2:Attribute FriendlyName=\"Domicilio fisico\" Name=\"address\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/><saml2:Attribute FriendlyName=\"Data di scadenza identit\u00c3\u00a0\" Name=\"expirationDate\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/><saml2:Attribute FriendlyName=\"Domicilio digitale\" Name=\"digitalAddress\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang=\"it\">ArubaPEC S.p.A.</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"it\">ArubaPEC S.p.A.</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"it\">https://www.pec.it/</md:OrganizationURL></md:Organization></md:EntityDescriptor>",
        "x509cert": "-----BEGIN CERTIFICATE-----\nMIIExTCCA62gAwIBAgIQIHtEvEhGM77HwqsuvSbi9zANBgkqhkiG9w0BAQsFADBsMQswCQYDVQQG\nEwJJVDEYMBYGA1UECgwPQXJ1YmFQRUMgUy5wLkEuMSEwHwYDVQQLDBhDZXJ0aWZpY2F0aW9uIEF1\ndGhvcml0eUIxIDAeBgNVBAMMF0FydWJhUEVDIFMucC5BLiBORyBDQSAyMB4XDTE3MDEyMzAwMDAw\nMFoXDTIwMDEyMzIzNTk1OVowgaAxCzAJBgNVBAYTAklUMRYwFAYDVQQKDA1BcnViYSBQRUMgc3Bh\nMREwDwYDVQQLDAhQcm9kb3R0bzEWMBQGA1UEAwwNcGVjLml0IHBlYy5pdDEZMBcGA1UEBRMQWFhY\nWFhYMDBYMDBYMDAwWDEPMA0GA1UEKgwGcGVjLml0MQ8wDQYDVQQEDAZwZWMuaXQxETAPBgNVBC4T\nCDE2MzQ1MzgzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqt2oHJhcp03l73p+QYpE\nJ+f3jYYj0W0gos0RItZx/w4vpsiKBygaqDNVWSwfo1aPdVDIX13f62O+lBki29KTt+QWv5K6SGHD\nUXYPntRdEQlicIBh2Z0HfrM7fDl+xeJrMp1s4dsSQAuB5TJOlFZq7xCQuukytGWBTvjfcN/os5aE\nsEg+RbtZHJR26SbbUcIqWb27Swgj/9jwK+tvzLnP4w8FNvEOrNfR0XwTMNDFrwbOCuWgthv5jNBs\nVZaoqNwiA/MxYt+gTOMj/o5PWKk8Wpm6o/7/+lWAoxh0v8x9OkbIi+YaFpIxuCcUqsrJJk63x2gH\nCc2nr+yclYUhsKD/AwIDAQABo4IBLDCCASgwDgYDVR0PAQH/BAQDAgeAMB0GA1UdDgQWBBTKQ3+N\nPGcXFk8nX994vMTVpba1EzBHBgNVHSAEQDA+MDwGCysGAQQBgegtAQEBMC0wKwYIKwYBBQUHAgEW\nH2h0dHBzOi8vY2EuYXJ1YmFwZWMuaXQvY3BzLmh0bWwwWAYDVR0fBFEwTzBNoEugSYZHaHR0cDov\nL2NybC5hcnViYXBlYy5pdC9BcnViYVBFQ1NwQUNlcnRpZmljYXRpb25BdXRob3JpdHlCL0xhdGVz\ndENSTC5jcmwwHwYDVR0jBBgwFoAU8v9jQBwRQv3M3/FZ9m7omYcxR3kwMwYIKwYBBQUHAQEEJzAl\nMCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5hcnViYXBlYy5pdDANBgkqhkiG9w0BAQsFAAOCAQEA\nnEw0NuaspbpDjA5wggwFtfQydU6b3Bw2/KXPRKS2JoqGmx0SYKj+L17A2KUBa2c7gDtKXYz0FLT6\n0Bv0pmBN/oYCgVMEBJKqwRwdki9YjEBwyCZwNEx1kDAyyqFEVU9vw/OQfrAdp7MTbuZGFKknVt7b\n9wOYy/Op9FiUaTg6SuOy0ep+rqhihltYNAAl4L6fY45mHvqa5vvVG30OvLW/S4uvRYUXYwY6KhWv\nNdDf5CnFugnuEZtHJrVe4wx9aO5GvFLFZ/mQ35C5mXPQ7nIb0CDdLBJdz82nUoLSA5BUbeXAUkfa\nhW/hLxLdhks68/TK694xVIuiB40pvMmJwxIyDA==\n-----END CERTIFICATE-----",
        "x509certFingerPrint": "1be9f6fbbb04d9be521e626bdaf4fb13faed5849"
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (62, '3f87c063-837c-4783-aaa0-9c0c4d386080', '401', 'http://192.168.56.103:8888/api/prvd/sapienza/metadata/verify', '2017-07-24 07:21:13.672003+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "easyspid104",
        "httpcode": 401,
        "message": "Invalid XML"
    },
    "id": "1c916b94-1c39-4ba1-853a-41a80dd52185",
    "result": {
        "metadataValidate": {
            "signCheck": 0,
            "validate": [
                "unloaded_xml"
            ]
        }
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (63, '211ed0f6-8703-4b89-8d07-d6047c991830', '404', 'http://192.168.56.103:8888/api/prvd/infocert/metadata/verify', '2017-07-24 07:24:08.976632+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "easyspid101",
        "httpcode": 404,
        "message": "Sp not found"
    },
    "id": "6079db80-5c84-4102-8812-9afa2d6bd13c",
    "result": null
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (64, 'bb1c8a1e-6104-45bd-b74e-5161fea6a692', '404', 'http://192.168.56.103:8888/api/prvd/infocrt/metadata/verify', '2017-07-24 07:24:30.836177+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "easyspid101",
        "httpcode": 404,
        "message": "Sp not found"
    },
    "id": "3991469f-95fb-4e36-b8ed-01b142dbc2c3",
    "result": null
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (65, '7b88acc5-1055-49d3-8ba1-e072814dc59b', '200', 'http://192.168.56.103:8888/api/prvd/infocrt/metadata', '2017-07-24 07:25:47.39698+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "200",
        "httpcode": 200,
        "message": "OK"
    },
    "id": "6db967fe-5e4f-4f2c-8064-a38e7323ad0f",
    "result": {
        "fingerPrintAlg": "sha1",
        "key": null,
        "metadata": "<?xml version=\"1.0\" standalone=\"no\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"_25b183c4c721960977003fb04ec600b4\" cacheDuration=\"P0Y0M30DT0H0M0.000S\" entityID=\"https://identity.infocert.it\"><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"#_25b183c4c721960977003fb04ec600b4\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>hKbiiLWanDYNT69FQLh4uWlI6rVdAfoNXltq8WE83No=</DigestValue></Reference></SignedInfo><SignatureValue>nqWCyBqw40iHn3OEF9qVnJIzX9xmTzoq3EE9pbpPtrrAnjBWKTI2GxCAH84oD7BArJ/oBWOEQ0iJzFLwdtJK56ly8MwFAiYdCuNm9wHd03gSGBMxaWbhQSfwkwRCmMbzxcXJGMhh4JECOdZ87KR861A+S2EPyWBHC9yx8iRZ4UtmrGpf3UWyFJsCEjCLZv+a/ld6WnkP43OqJhs84BQWrH+Z1QOy1GDDYe+sItvQ1BhOomDT6x+ZsrMntgAItF+1kQxJ5CPRzGkYb10vr0WYukAAfcQ46fJ7Jje5ZBG8heBd61wxwKfuDDt6MD191PLWHjgy6sgA6zwXikGkQsTeeA==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIGbDCCBVSgAwIBAgIDA+76MA0GCSqGSIb3DQEBCwUAMIGGMQswCQYDVQQGEwJJVDEVMBMGA1UECgwMSU5GT0NFUlQgU1BBMRswGQYDVQQLDBJFbnRlIENlcnRpZmljYXRvcmUxFDASBgNVBAUTCzA3OTQ1MjExMDA2MS0wKwYDVQQDDCRJbmZvQ2VydCBTZXJ2aXppIGRpIENlcnRpZmljYXppb25lIDIwHhcNMTYwMTEyMDkyNDI4WhcNMTkwMTEyMDAwMDAwWjCBsTEUMBIGA1UELhMLMDc5NDUyMTEwMDYxDzANBgkqhkiG9w0BCQEWADEUMBIGA1UEBRMLMDc5NDUyMTEwMDYxHTAbBgNVBAMMFGlkZW50aXR5LmluZm9jZXJ0Lml0MRQwEgYDVQQLDAtJbmZvQ2VydCBJRDEhMB8GA1UECgwYSW5mb0NlcnQgU3BBLzA3OTQ1MjExMDA2MQ0wCwYDVQQHDARSb21hMQswCQYDVQQGEwJJVDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALDysrpnXB+it94LSuAmOgyFDilZ8nuSEVOFl1PX/HtgK3W25B/tqJBsyZwrAIXxg5XHYd3+i7bFoBjuduzfqhvSv9WYCVtggsz5a3sbOpU54DaOLgoCmd4nIsINwKzCmT1UNXBGjS+Xt5F3lV+v2Ayr4rAsPnkE2084BLmwcIX3w7+rx/Nd+/5HfaAMaORICYinUIvbZ5e/plUj87s1YEpep/DcC0uMFE66jFrcnHVOeHCrDh+tAZAiGew4BVJjLr0hfS4ZeaE43TJlHb00GZNfpfzGcOPbzWlSB5iF/cZbTRHmPsn0gALfpPNViniFBVqSaoywZwvkFosrehRUCNkCAwEAAaOCArQwggKwMBMGA1UdJQQMMAoGCCsGAQUFBwMCMCUGA1UdEgQeMByBGmZpcm1hLmRpZ2l0YWxlQGluZm9jZXJ0Lml0MGUGA1UdIAReMFwwWgYGK0wkAQEIMFAwTgYIKwYBBQUHAgIwQgxASW5mb0NlcnQgU3BBIFNTTCwgU01JTUUgYW5kIGRpZ2l0YWwgc2lnbmF0dXJlIENsaWVudCBDZXJ0aWZpY2F0ZTA3BggrBgEFBQcBAQQrMCkwJwYIKwYBBQUHMAGGG2h0dHA6Ly9vY3NwLnNjLmluZm9jZXJ0Lml0LzCB7AYDVR0fBIHkMIHhMDSgMqAwhi5odHRwOi8vY3JsLmluZm9jZXJ0Lml0L2NybHMvc2Vydml6aTIvQ1JMMDEuY3JsMIGooIGloIGihoGfbGRhcDovL2xkYXAuaW5mb2NlcnQuaXQvY24lM0RJbmZvQ2VydCUyMFNlcnZpemklMjBkaSUyMENlcnRpZmljYXppb25lJTIwMiUyMENSTDAxLG91JTNERW50ZSUyMENlcnRpZmljYXRvcmUsbyUzRElORk9DRVJUJTIwU1BBLEMlM0RJVD9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0MA4GA1UdDwEB/wQEAwIEsDCBswYDVR0jBIGrMIGogBTpNppkKVKhWv5ppMSDt4B9D2oSeKGBjKSBiTCBhjELMAkGA1UEBhMCSVQxFTATBgNVBAoMDElORk9DRVJUIFNQQTEbMBkGA1UECwwSRW50ZSBDZXJ0aWZpY2F0b3JlMRQwEgYDVQQFEwswNzk0NTIxMTAwNjEtMCsGA1UEAwwkSW5mb0NlcnQgU2Vydml6aSBkaSBDZXJ0aWZpY2F6aW9uZSAyggECMB0GA1UdDgQWBBTi8mIRU4ue/0lKSfv4gSQhoZQvozANBgkqhkiG9w0BAQsFAAOCAQEAUCXyjmfzxmyVQbK4cf79zj5qMZVAAjDMTR1UGFcS2IibICh3S3Uf22lPGQfm+MX9tiweETW7fBLW6lrR2ofXBz/FfU98A/AA9GZDrbGhBxoc+RoqkHVYRqEuXOq6z3X9DuvsdsfKeO3p4eXbXlCcxD2PP5fFqcZxx1WZ1HRamiGk9fMN1iT3aPa3q7TfRD6W6+XgafjXieZ8bCa1FGIfapbqsWa91jdn4xiJpbmTTq1/Zjs5RCZYzmMEV9rSuSVgFtONb8+xKC4ohMVxAUw2yZHwd4dDyBLkapuaWkzhW939+gjeoKz04Ds2C52d/kln7ehdu9LkzvRI6UAEpAYLgg==</X509Certificate></X509Data></KeyInfo></Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIIGbDCCBVSgAwIBAgIDA+76MA0GCSqGSIb3DQEBCwUAMIGGMQswCQYDVQQGEwJJVDEVMBMGA1UECgwMSU5GT0NFUlQgU1BBMRswGQYDVQQLDBJFbnRlIENlcnRpZmljYXRvcmUxFDASBgNVBAUTCzA3OTQ1MjExMDA2MS0wKwYDVQQDDCRJbmZvQ2VydCBTZXJ2aXppIGRpIENlcnRpZmljYXppb25lIDIwHhcNMTYwMTEyMDkyNDI4WhcNMTkwMTEyMDAwMDAwWjCBsTEUMBIGA1UELhMLMDc5NDUyMTEwMDYxDzANBgkqhkiG9w0BCQEWADEUMBIGA1UEBRMLMDc5NDUyMTEwMDYxHTAbBgNVBAMMFGlkZW50aXR5LmluZm9jZXJ0Lml0MRQwEgYDVQQLDAtJbmZvQ2VydCBJRDEhMB8GA1UECgwYSW5mb0NlcnQgU3BBLzA3OTQ1MjExMDA2MQ0wCwYDVQQHDARSb21hMQswCQYDVQQGEwJJVDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALDysrpnXB+it94LSuAmOgyFDilZ8nuSEVOFl1PX/HtgK3W25B/tqJBsyZwrAIXxg5XHYd3+i7bFoBjuduzfqhvSv9WYCVtggsz5a3sbOpU54DaOLgoCmd4nIsINwKzCmT1UNXBGjS+Xt5F3lV+v2Ayr4rAsPnkE2084BLmwcIX3w7+rx/Nd+/5HfaAMaORICYinUIvbZ5e/plUj87s1YEpep/DcC0uMFE66jFrcnHVOeHCrDh+tAZAiGew4BVJjLr0hfS4ZeaE43TJlHb00GZNfpfzGcOPbzWlSB5iF/cZbTRHmPsn0gALfpPNViniFBVqSaoywZwvkFosrehRUCNkCAwEAAaOCArQwggKwMBMGA1UdJQQMMAoGCCsGAQUFBwMCMCUGA1UdEgQeMByBGmZpcm1hLmRpZ2l0YWxlQGluZm9jZXJ0Lml0MGUGA1UdIAReMFwwWgYGK0wkAQEIMFAwTgYIKwYBBQUHAgIwQgxASW5mb0NlcnQgU3BBIFNTTCwgU01JTUUgYW5kIGRpZ2l0YWwgc2lnbmF0dXJlIENsaWVudCBDZXJ0aWZpY2F0ZTA3BggrBgEFBQcBAQQrMCkwJwYIKwYBBQUHMAGGG2h0dHA6Ly9vY3NwLnNjLmluZm9jZXJ0Lml0LzCB7AYDVR0fBIHkMIHhMDSgMqAwhi5odHRwOi8vY3JsLmluZm9jZXJ0Lml0L2NybHMvc2Vydml6aTIvQ1JMMDEuY3JsMIGooIGloIGihoGfbGRhcDovL2xkYXAuaW5mb2NlcnQuaXQvY24lM0RJbmZvQ2VydCUyMFNlcnZpemklMjBkaSUyMENlcnRpZmljYXppb25lJTIwMiUyMENSTDAxLG91JTNERW50ZSUyMENlcnRpZmljYXRvcmUsbyUzRElORk9DRVJUJTIwU1BBLEMlM0RJVD9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0MA4GA1UdDwEB/wQEAwIEsDCBswYDVR0jBIGrMIGogBTpNppkKVKhWv5ppMSDt4B9D2oSeKGBjKSBiTCBhjELMAkGA1UEBhMCSVQxFTATBgNVBAoMDElORk9DRVJUIFNQQTEbMBkGA1UECwwSRW50ZSBDZXJ0aWZpY2F0b3JlMRQwEgYDVQQFEwswNzk0NTIxMTAwNjEtMCsGA1UEAwwkSW5mb0NlcnQgU2Vydml6aSBkaSBDZXJ0aWZpY2F6aW9uZSAyggECMB0GA1UdDgQWBBTi8mIRU4ue/0lKSfv4gSQhoZQvozANBgkqhkiG9w0BAQsFAAOCAQEAUCXyjmfzxmyVQbK4cf79zj5qMZVAAjDMTR1UGFcS2IibICh3S3Uf22lPGQfm+MX9tiweETW7fBLW6lrR2ofXBz/FfU98A/AA9GZDrbGhBxoc+RoqkHVYRqEuXOq6z3X9DuvsdsfKeO3p4eXbXlCcxD2PP5fFqcZxx1WZ1HRamiGk9fMN1iT3aPa3q7TfRD6W6+XgafjXieZ8bCa1FGIfapbqsWa91jdn4xiJpbmTTq1/Zjs5RCZYzmMEV9rSuSVgFtONb8+xKC4ohMVxAUw2yZHwd4dDyBLkapuaWkzhW939+gjeoKz04Ds2C52d/kln7ehdu9LkzvRI6UAEpAYLgg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlsso\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlsso\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio fisico\" Name=\"address\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Ragione o denominazione sociale\" Name=\"companyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Provincia di nascita\" Name=\"countyOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di nascita\" Name=\"dateOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio digitale\" Name=\"digitalAddress\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Indirizzo di posta elettronica\" Name=\"email\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di scadenza identita\" Name=\"expirationDate\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Cognome\" Name=\"familyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice fiscale\" Name=\"fiscalNumber\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sesso\" Name=\"gender\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Documento d''identita\" Name=\"idCard\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Partita IVA\" Name=\"ivaCode\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Numero di telefono mobile\" Name=\"mobilePhone\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Nome\" Name=\"name\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Luogo di nascita\" Name=\"placeOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sede legale\" Name=\"registeredOffice\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice identificativo SPID\" Name=\"spidCode\"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"it\">https://www.infocert.it</md:OrganizationURL><md:OrganizationURL xml:lang=\"en\">https://www.infocert.it/international/?lang=en</md:OrganizationURL><md:OrganizationURL xml:lang=\"fr\">https://www.infocert.it/international/?lang=fr</md:OrganizationURL><md:OrganizationURL xml:lang=\"de\">https://www.infocert.it/international/?lang=de</md:OrganizationURL></md:Organization></md:EntityDescriptor>\r\r",
        "x509cert": "-----BEGIN CERTIFICATE-----\n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\n-----END CERTIFICATE-----",
        "x509certFingerPrint": "a0dbf5fe457e742cc606acb0e093e9ea1e965942"
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (66, '491f1829-3cc4-4228-8ac3-bb2aa6718d8e', '404', 'http://192.168.56.103:8888/api/prvd/infocrt/metadata/verify', '2017-07-24 07:29:21.24875+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "easyspid101",
        "httpcode": 404,
        "message": "Sp not found"
    },
    "id": "d0bba2eb-2d46-49a9-a73b-fc3a70dbb427",
    "result": null
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (67, '3213999b-c051-46f7-be3f-66669561ddc8', '500', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 12:48:28.340898+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "500",
        "httpcode": 500,
        "message": "Internal Server Error"
    },
    "id": "423a61f0-9ecd-42c8-ac38-192e4cd56c15",
    "result": null
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (68, '5cd7ea1d-1b82-4ea4-ae9e-2f7881535ce9', '500', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 12:53:15.54671+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "500",
        "httpcode": 500,
        "message": "Internal Server Error"
    },
    "id": "bb76b74f-8821-418a-bde5-8466e46e4c9c",
    "result": null
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (69, '6879736d-ced6-49c4-8e43-44676cb86730', '500', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 13:00:44.072943+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "500",
        "debugMessage": {
            "py/reduce": [
                {
                    "py/type": "__builtin__.AttributeError"
                },
                [
                    "''str'' object has no attribute ''tex''"
                ],
                {},
                null,
                null
            ]
        },
        "httpcode": 500,
        "message": "Internal Server Error"
    },
    "id": "943cf1c2-3ca4-4171-a3b8-7dc27e14ef49",
    "result": null
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (70, '67e165a1-f133-46d2-b124-39a6ba007670', '500', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 13:03:51.036566+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "500",
        "debugMessage": {
            "py/reduce": [
                {
                    "py/type": "__builtin__.AttributeError"
                },
                [
                    "''str'' object has no attribute ''tex''"
                ],
                {},
                null,
                null
            ]
        },
        "httpcode": 500,
        "message": "Internal Server Error"
    },
    "id": "1af7b34e-b4f1-4bc3-8677-536e567cb699",
    "result": null
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (71, '137bf705-8dc5-4404-9575-d89c56810b71', '500', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 15:54:04.34489+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "500",
        "debugMessage": {
            "py/reduce": [
                {
                    "py/type": "__builtin__.AttributeError"
                },
                [
                    "''str'' object has no attribute ''tex''"
                ],
                {},
                null,
                null
            ]
        },
        "httpcode": 500,
        "message": "Internal Server Error"
    },
    "id": "25ba783f-f634-4993-bb3e-c2179d3406a1",
    "result": null
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (72, 'a40db1b1-3a69-40e7-b723-260dc78ddf96', '500', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 16:01:56.483372+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "500",
        "debugMessage": {
            "py/reduce": [
                {
                    "py/type": "__builtin__.AttributeError"
                },
                [
                    "type object ''OneLogin_Saml2_XML'' has no attribute ''vavalidate_xml''"
                ],
                {},
                null,
                null
            ]
        },
        "httpcode": 500,
        "message": "Internal Server Error"
    },
    "id": "c751ae91-4586-47c1-b448-dbdc8180c43a",
    "result": null
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (73, 'f39088b4-5a6e-4b10-a8e4-f6c01f5259c1', '500', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 16:41:10.324264+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "500",
        "debugMessage": {
            "py/reduce": [
                {
                    "py/type": "__builtin__.TypeError"
                },
                [
                    "''module'' object is not callable"
                ],
                {},
                null,
                null
            ]
        },
        "httpcode": 500,
        "message": "Internal Server Error"
    },
    "id": "5425c555-f5d2-416c-a800-c646c95d4bdc",
    "result": null
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (74, '2d9c7dbc-ce7f-4c24-b78b-0bcc97448a47', '200', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 16:41:57.818585+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "200",
        "httpcode": 200,
        "message": "OK"
    },
    "id": "838f71f4-fec0-4c96-be5b-8fef64da7490",
    "result": {
        "metadataValidate": {
            "certValidity": 1,
            "signCheck": 1,
            "validate": []
        }
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (75, 'ff6fcb54-1cf9-4a8a-9993-365b05c5341f', '200', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 16:42:35.00223+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "200",
        "httpcode": 200,
        "message": "OK"
    },
    "id": "ccc7b8e0-5881-474d-91ba-219d8488fee9",
    "result": {
        "metadataValidate": {
            "certValidity": 1,
            "signCheck": 1,
            "validate": []
        }
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (76, '1c5b55cc-eb1c-42e9-9c4a-1038eb65172b', '401', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 16:43:13.21828+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "easyspid106",
        "httpcode": 401,
        "message": "Invalid XML signature"
    },
    "id": "ca8bf6d5-f249-4e4d-b1f0-85f94558a862",
    "result": {
        "metadataValidate": {
            "certValidity": 1,
            "signCheck": 0,
            "validate": []
        }
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (77, '1798a6e1-f84d-47c5-9c94-72209e85216d', '200', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 16:46:38.434482+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "200",
        "httpcode": 200,
        "message": "OK"
    },
    "id": "5aa50a5a-5768-4b4c-9726-5d26bc8ab683",
    "result": {
        "metadataValidate": {
            "certValidity": 1,
            "signCheck": 1,
            "validate": []
        }
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (78, 'a4090e21-4006-4bdf-bba0-1360971aa206', '200', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 16:47:01.206947+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "200",
        "httpcode": 200,
        "message": "OK"
    },
    "id": "9e6caf77-92f8-4476-b196-014d72557e17",
    "result": {
        "metadataValidate": {
            "certValidity": 1,
            "signCheck": 1,
            "validate": []
        }
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (79, '55f5fc60-c8c2-4aca-9687-30f3c39bf837', '401', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 16:47:18.012521+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "easyspid106",
        "httpcode": 401,
        "message": "Invalid XML signature"
    },
    "id": "dfaa3adf-8cc6-456a-9e67-8550ac5fe26b",
    "result": {
        "metadataValidate": {
            "certValidity": 1,
            "signCheck": 0,
            "validate": []
        }
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (80, '2a83022d-29c5-4c5e-940f-da39bbd1a5b8', '200', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 16:47:29.056407+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "200",
        "httpcode": 200,
        "message": "OK"
    },
    "id": "93106208-8504-4850-a30f-b96b75cce9fc",
    "result": {
        "metadataValidate": {
            "certValidity": 1,
            "signCheck": 1,
            "validate": []
        }
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (81, 'e88ba9b0-d9dc-474d-b13f-6a20a20fe0e9', '500', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 17:02:51.631771+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "500",
        "debugMessage": {
            "py/reduce": [
                {
                    "py/type": "__builtin__.UnboundLocalError"
                },
                [
                    "local variable ''certFingerprint'' referenced before assignment"
                ],
                {},
                null,
                null
            ]
        },
        "httpcode": 500,
        "message": "Internal Server Error"
    },
    "id": "5e4544bb-7190-4661-b7d6-542f3d51abba",
    "result": null
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (82, 'de330528-be81-46a9-9cee-8ec673f893ca', '200', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 17:03:19.761003+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "200",
        "httpcode": 200,
        "message": "OK"
    },
    "id": "6c32a68b-4ff2-4dd9-87f3-32f3d7ac53e1",
    "result": {
        "metadataValidate": {
            "certValidity": 1,
            "certallowed": 1,
            "signCheck": 1,
            "validate": []
        }
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (83, '5d0b51eb-4bb2-4b94-b29b-b86d933e127a', '200', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 17:08:27.175148+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "200",
        "httpcode": 200,
        "message": "OK"
    },
    "id": "5dd2d02e-72c3-4db0-969b-ff72f3f12047",
    "result": {
        "metadataValidate": {
            "certValidity": 1,
            "certallowed": 1,
            "signCheck": 1,
            "validate": []
        }
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (84, '2b96915f-a78e-40fa-85e0-1a022dbea04d', '500', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 17:09:57.175942+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "500",
        "debugMessage": {
            "py/reduce": [
                {
                    "py/type": "__builtin__.TypeError"
                },
                [
                    "''int'' object is not subscriptable"
                ],
                {},
                null,
                null
            ]
        },
        "httpcode": 500,
        "message": "Internal Server Error"
    },
    "id": "4aaaf67e-f7a0-45b0-8514-21ec55d6d227",
    "result": null
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (85, 'f647c210-abde-46b0-adcd-73e546da1f39', '200', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 17:11:04.729072+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "200",
        "httpcode": 200,
        "message": "OK"
    },
    "id": "d8580eac-4422-4be4-8edb-b5def84b3a28",
    "result": {
        "metadataValidate": {
            "certValidity": 1,
            "certallowed": 0,
            "signCheck": 1,
            "validate": []
        }
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (86, '943d459d-adcd-4b95-91a4-347465a3aefe', '200', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 17:11:17.036728+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "200",
        "httpcode": 200,
        "message": "OK"
    },
    "id": "a0091800-5ca2-4b5a-b8f5-a07591f1e565",
    "result": {
        "metadataValidate": {
            "certValidity": 1,
            "certallowed": 0,
            "signCheck": 1,
            "validate": []
        }
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (87, '14a85164-fade-43f4-ba45-26e32b3153a4', '200', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 17:17:08.53689+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "200",
        "httpcode": 200,
        "message": "OK"
    },
    "id": "c2d278f7-cbbc-4150-80aa-881a71d3e5f0",
    "result": {
        "metadataValidate": {
            "certValidity": 1,
            "certallowed": 1,
            "signCheck": 1,
            "validate": []
        }
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (88, '8a4461c2-465a-4a0c-a88e-8776de9c80cf', '200', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 17:17:17.916053+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "200",
        "httpcode": 200,
        "message": "OK"
    },
    "id": "4a0c2240-090a-4314-bac2-0cf57acd559f",
    "result": {
        "metadataValidate": {
            "certValidity": 1,
            "certallowed": 0,
            "signCheck": 1,
            "validate": []
        }
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (89, '767c858a-6d14-4a75-9e1a-fe6617abfac2', '404', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 17:17:24.234773+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "easyspid101",
        "httpcode": 404,
        "message": "Sp not found"
    },
    "id": "57a5b14f-53c6-4c63-b9ae-ec3e60754a67",
    "result": null
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (90, '8e2c82b9-c28e-4d22-963d-d66ee43a3ea9', '404', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 17:19:37.528018+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "easyspid112",
        "httpcode": 404,
        "message": "Provider public keu not found"
    },
    "id": "5b45626d-3f6a-4b11-a952-4df019fc8daa",
    "result": null
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (91, '892b20b3-56bd-413a-a323-d6701ad133c0', '200', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 17:20:03.616497+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "200",
        "httpcode": 200,
        "message": "OK"
    },
    "id": "60f67e0f-32e7-454b-b605-8537f975473b",
    "result": {
        "metadataValidate": {
            "certValidity": 1,
            "certallowed": 1,
            "signCheck": 1,
            "validate": []
        }
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (92, '5a2c814a-1acd-4aa7-b698-0da84a6a9522', '200', 'http://192.168.56.103:8888/api/prvd/infocrt/metadata', '2017-07-24 17:21:23.616806+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "200",
        "httpcode": 200,
        "message": "OK"
    },
    "id": "7830cef9-e32f-48dd-9c5e-0d2b97fe7a84",
    "result": {
        "fingerPrintAlg": "sha1",
        "key": null,
        "metadata": "<?xml version=\"1.0\" standalone=\"no\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"_25b183c4c721960977003fb04ec600b4\" cacheDuration=\"P0Y0M30DT0H0M0.000S\" entityID=\"https://identity.infocert.it\"><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"#_25b183c4c721960977003fb04ec600b4\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>hKbiiLWanDYNT69FQLh4uWlI6rVdAfoNXltq8WE83No=</DigestValue></Reference></SignedInfo><SignatureValue>nqWCyBqw40iHn3OEF9qVnJIzX9xmTzoq3EE9pbpPtrrAnjBWKTI2GxCAH84oD7BArJ/oBWOEQ0iJzFLwdtJK56ly8MwFAiYdCuNm9wHd03gSGBMxaWbhQSfwkwRCmMbzxcXJGMhh4JECOdZ87KR861A+S2EPyWBHC9yx8iRZ4UtmrGpf3UWyFJsCEjCLZv+a/ld6WnkP43OqJhs84BQWrH+Z1QOy1GDDYe+sItvQ1BhOomDT6x+ZsrMntgAItF+1kQxJ5CPRzGkYb10vr0WYukAAfcQ46fJ7Jje5ZBG8heBd61wxwKfuDDt6MD191PLWHjgy6sgA6zwXikGkQsTeeA==</SignatureValue><KeyInfo><X509Data><X509Certificate>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</X509Certificate></X509Data></KeyInfo></Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlsso\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlsso\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio fisico\" Name=\"address\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Ragione o denominazione sociale\" Name=\"companyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Provincia di nascita\" Name=\"countyOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di nascita\" Name=\"dateOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio digitale\" Name=\"digitalAddress\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Indirizzo di posta elettronica\" Name=\"email\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di scadenza identita\" Name=\"expirationDate\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Cognome\" Name=\"familyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice fiscale\" Name=\"fiscalNumber\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sesso\" Name=\"gender\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Documento d''identita\" Name=\"idCard\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Partita IVA\" Name=\"ivaCode\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Numero di telefono mobile\" Name=\"mobilePhone\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Nome\" Name=\"name\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Luogo di nascita\" Name=\"placeOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sede legale\" Name=\"registeredOffice\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice identificativo SPID\" Name=\"spidCode\"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"it\">https://www.infocert.it</md:OrganizationURL><md:OrganizationURL xml:lang=\"en\">https://www.infocert.it/international/?lang=en</md:OrganizationURL><md:OrganizationURL xml:lang=\"fr\">https://www.infocert.it/international/?lang=fr</md:OrganizationURL><md:OrganizationURL xml:lang=\"de\">https://www.infocert.it/international/?lang=de</md:OrganizationURL></md:Organization></md:EntityDescriptor>\r\r",
        "x509cert": "-----BEGIN CERTIFICATE-----\n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\n-----END CERTIFICATE-----",
        "x509certFingerPrint": "a0dbf5fe457e742cc606acb0e093e9ea1e965942"
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (93, 'ad6adca5-2830-4651-bd92-a62f87fffea8', '200', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 17:21:46.581533+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "200",
        "httpcode": 200,
        "message": "OK"
    },
    "id": "5af59505-f5d3-4707-8cf1-a831c7f32107",
    "result": {
        "metadataValidate": {
            "certValidity": 1,
            "certallowed": 1,
            "signCheck": 1,
            "validate": []
        }
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (94, '25880fb0-b78c-4627-823d-cff7fca456c6', '401', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 17:22:00.31856+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "easyspid106",
        "httpcode": 401,
        "message": "Invalid XML signature"
    },
    "id": "412a495f-9d4d-4e47-85ce-348f84b44302",
    "result": {
        "metadataValidate": {
            "certValidity": 1,
            "certallowed": 1,
            "signCheck": 0,
            "validate": []
        }
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (95, '3c3f16ac-c891-4169-83dd-aa15f1a26315', '200', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-24 17:22:10.761429+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "200",
        "httpcode": 200,
        "message": "OK"
    },
    "id": "5b58d30a-b4d2-4ba7-8230-97872d585e47",
    "result": {
        "metadataValidate": {
            "certValidity": 1,
            "certallowed": 1,
            "signCheck": 1,
            "validate": []
        }
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (96, 'ee9bd860-2784-4bb5-806d-392bcb73525a', '200', 'http://192.168.56.103:8888/api/prvd/infocrt/metadata', '2017-07-25 10:42:46.785264+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "200",
        "httpcode": 200,
        "message": "OK"
    },
    "id": "1cefde8a-de2e-42a3-9b78-7f6ffecdee74",
    "result": {
        "fingerPrintAlg": "sha1",
        "key": null,
        "metadata": "<?xml version=\"1.0\" standalone=\"no\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"_25b183c4c721960977003fb04ec600b4\" cacheDuration=\"P0Y0M30DT0H0M0.000S\" entityID=\"https://identity.infocert.it\"><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"#_25b183c4c721960977003fb04ec600b4\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>hKbiiLWanDYNT69FQLh4uWlI6rVdAfoNXltq8WE83No=</DigestValue></Reference></SignedInfo><SignatureValue>nqWCyBqw40iHn3OEF9qVnJIzX9xmTzoq3EE9pbpPtrrAnjBWKTI2GxCAH84oD7BArJ/oBWOEQ0iJzFLwdtJK56ly8MwFAiYdCuNm9wHd03gSGBMxaWbhQSfwkwRCmMbzxcXJGMhh4JECOdZ87KR861A+S2EPyWBHC9yx8iRZ4UtmrGpf3UWyFJsCEjCLZv+a/ld6WnkP43OqJhs84BQWrH+Z1QOy1GDDYe+sItvQ1BhOomDT6x+ZsrMntgAItF+1kQxJ5CPRzGkYb10vr0WYukAAfcQ46fJ7Jje5ZBG8heBd61wxwKfuDDt6MD191PLWHjgy6sgA6zwXikGkQsTeeA==</SignatureValue><KeyInfo><X509Data><X509Certificate>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</X509Certificate></X509Data></KeyInfo></Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIIGbDCCBVSgAwIBAgIDA+76MA0GCSqGSIb3DQEBCwUAMIGGMQswCQYDVQQGEwJJVDEVMBMGA1UECgwMSU5GT0NFUlQgU1BBMRswGQYDVQQLDBJFbnRlIENlcnRpZmljYXRvcmUxFDASBgNVBAUTCzA3OTQ1MjExMDA2MS0wKwYDVQQDDCRJbmZvQ2VydCBTZXJ2aXppIGRpIENlcnRpZmljYXppb25lIDIwHhcNMTYwMTEyMDkyNDI4WhcNMTkwMTEyMDAwMDAwWjCBsTEUMBIGA1UELhMLMDc5NDUyMTEwMDYxDzANBgkqhkiG9w0BCQEWADEUMBIGA1UEBRMLMDc5NDUyMTEwMDYxHTAbBgNVBAMMFGlkZW50aXR5LmluZm9jZXJ0Lml0MRQwEgYDVQQLDAtJbmZvQ2VydCBJRDEhMB8GA1UECgwYSW5mb0NlcnQgU3BBLzA3OTQ1MjExMDA2MQ0wCwYDVQQHDARSb21hMQswCQYDVQQGEwJJVDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALDysrpnXB+it94LSuAmOgyFDilZ8nuSEVOFl1PX/HtgK3W25B/tqJBsyZwrAIXxg5XHYd3+i7bFoBjuduzfqhvSv9WYCVtggsz5a3sbOpU54DaOLgoCmd4nIsINwKzCmT1UNXBGjS+Xt5F3lV+v2Ayr4rAsPnkE2084BLmwcIX3w7+rx/Nd+/5HfaAMaORICYinUIvbZ5e/plUj87s1YEpep/DcC0uMFE66jFrcnHVOeHCrDh+tAZAiGew4BVJjLr0hfS4ZeaE43TJlHb00GZNfpfzGcOPbzWlSB5iF/cZbTRHmPsn0gALfpPNViniFBVqSaoywZwvkFosrehRUCNkCAwEAAaOCArQwggKwMBMGA1UdJQQMMAoGCCsGAQUFBwMCMCUGA1UdEgQeMByBGmZpcm1hLmRpZ2l0YWxlQGluZm9jZXJ0Lml0MGUGA1UdIAReMFwwWgYGK0wkAQEIMFAwTgYIKwYBBQUHAgIwQgxASW5mb0NlcnQgU3BBIFNTTCwgU01JTUUgYW5kIGRpZ2l0YWwgc2lnbmF0dXJlIENsaWVudCBDZXJ0aWZpY2F0ZTA3BggrBgEFBQcBAQQrMCkwJwYIKwYBBQUHMAGGG2h0dHA6Ly9vY3NwLnNjLmluZm9jZXJ0Lml0LzCB7AYDVR0fBIHkMIHhMDSgMqAwhi5odHRwOi8vY3JsLmluZm9jZXJ0Lml0L2NybHMvc2Vydml6aTIvQ1JMMDEuY3JsMIGooIGloIGihoGfbGRhcDovL2xkYXAuaW5mb2NlcnQuaXQvY24lM0RJbmZvQ2VydCUyMFNlcnZpemklMjBkaSUyMENlcnRpZmljYXppb25lJTIwMiUyMENSTDAxLG91JTNERW50ZSUyMENlcnRpZmljYXRvcmUsbyUzRElORk9DRVJUJTIwU1BBLEMlM0RJVD9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0MA4GA1UdDwEB/wQEAwIEsDCBswYDVR0jBIGrMIGogBTpNppkKVKhWv5ppMSDt4B9D2oSeKGBjKSBiTCBhjELMAkGA1UEBhMCSVQxFTATBgNVBAoMDElORk9DRVJUIFNQQTEbMBkGA1UECwwSRW50ZSBDZXJ0aWZpY2F0b3JlMRQwEgYDVQQFEwswNzk0NTIxMTAwNjEtMCsGA1UEAwwkSW5mb0NlcnQgU2Vydml6aSBkaSBDZXJ0aWZpY2F6aW9uZSAyggECMB0GA1UdDgQWBBTi8mIRU4ue/0lKSfv4gSQhoZQvozANBgkqhkiG9w0BAQsFAAOCAQEAUCXyjmfzxmyVQbK4cf79zj5qMZVAAjDMTR1UGFcS2IibICh3S3Uf22lPGQfm+MX9tiweETW7fBLW6lrR2ofXBz/FfU98A/AA9GZDrbGhBxoc+RoqkHVYRqEuXOq6z3X9DuvsdsfKeO3p4eXbXlCcxD2PP5fFqcZxx1WZ1HRamiGk9fMN1iT3aPa3q7TfRD6W6+XgafjXieZ8bCa1FGIfapbqsWa91jdn4xiJpbmTTq1/Zjs5RCZYzmMEV9rSuSVgFtONb8+xKC4ohMVxAUw2yZHwd4dDyBLkapuaWkzhW939+gjeoKz04Ds2C52d/kln7ehdu9LkzvRI6UAEpAYLgg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlslo\" ResponseLocation=\"https://identity.infocert.it/spid/samlslo/response\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://identity.infocert.it/spid/samlsso\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://identity.infocert.it/spid/samlsso\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio fisico\" Name=\"address\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Ragione o denominazione sociale\" Name=\"companyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Provincia di nascita\" Name=\"countyOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di nascita\" Name=\"dateOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Domicilio digitale\" Name=\"digitalAddress\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Indirizzo di posta elettronica\" Name=\"email\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Data di scadenza identita\" Name=\"expirationDate\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Cognome\" Name=\"familyName\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice fiscale\" Name=\"fiscalNumber\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sesso\" Name=\"gender\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Documento d''identita\" Name=\"idCard\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Partita IVA\" Name=\"ivaCode\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Numero di telefono mobile\" Name=\"mobilePhone\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Nome\" Name=\"name\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Luogo di nascita\" Name=\"placeOfBirth\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Sede legale\" Name=\"registeredOffice\"/><saml2:Attribute xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" FriendlyName=\"Codice identificativo SPID\" Name=\"spidCode\"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationName><md:OrganizationDisplayName xml:lang=\"it\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"en\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"fr\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang=\"de\">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"it\">https://www.infocert.it</md:OrganizationURL><md:OrganizationURL xml:lang=\"en\">https://www.infocert.it/international/?lang=en</md:OrganizationURL><md:OrganizationURL xml:lang=\"fr\">https://www.infocert.it/international/?lang=fr</md:OrganizationURL><md:OrganizationURL xml:lang=\"de\">https://www.infocert.it/international/?lang=de</md:OrganizationURL></md:Organization></md:EntityDescriptor>\r\r",
        "x509cert": "-----BEGIN CERTIFICATE-----\n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\n-----END CERTIFICATE-----",
        "x509certFingerPrint": "a0dbf5fe457e742cc606acb0e093e9ea1e965942"
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (97, 'b81786d1-76e3-4f11-81d6-9948168da67a', '500', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-25 10:46:23.196482+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "500",
        "debugMessage": {
            "py/reduce": [
                {
                    "py/type": "__builtin__.KeyError"
                },
                [
                    "validate"
                ],
                {},
                null,
                null
            ]
        },
        "httpcode": 500,
        "message": "Internal Server Error"
    },
    "id": "b7d8bc5f-c0f5-4573-9833-6b3f3e03de0e",
    "result": null
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (98, '31ea15d9-07b8-4018-aee4-12cb00d1201f', '500', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-25 10:47:50.824943+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "500",
        "debugMessage": {
            "py/reduce": [
                {
                    "py/type": "__builtin__.KeyError"
                },
                [
                    "validate"
                ],
                {},
                null,
                null
            ]
        },
        "httpcode": 500,
        "message": "Internal Server Error"
    },
    "id": "75f1ba5c-3e87-4ac1-85fc-1adf54385e83",
    "result": null
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (99, '7ae25994-f31f-45b8-8fc6-583d9daa80d1', '401', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-25 10:48:41.834512+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "easyspid106",
        "httpcode": 401,
        "message": "Invalid XML signature"
    },
    "id": "8862de95-528e-465c-a996-69337879289b",
    "result": {
        "metadataValidate": {
            "certAllowed": true,
            "certValidity": true,
            "error": 0,
            "msg": "",
            "schemaValidate": false,
            "signCheck": false
        }
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (100, 'a1cbb1e8-0320-4092-825e-ee65fd7933a2', '500', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-25 11:01:14.37273+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "500",
        "debugMessage": {
            "py/reduce": [
                {
                    "py/type": "__builtin__.TypeError"
                },
                [
                    "object of type ''bool'' has no len()"
                ],
                {},
                null,
                null
            ]
        },
        "httpcode": 500,
        "message": "Internal Server Error"
    },
    "id": "0edb37fb-bf9a-4fed-8258-76e874e7c551",
    "result": null
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (101, '56e182e2-0d87-4bce-8205-a3b85126e98a', '401', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-25 11:06:54.388746+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "easyspid104",
        "httpcode": 401,
        "message": "Invalid XML"
    },
    "id": "94c49556-2316-4e92-bda8-08401182447e",
    "result": {
        "metadataValidate": {
            "certAllowed": true,
            "certValidity": true,
            "error": 0,
            "msg": "",
            "schemaValidate": false,
            "signCheck": true
        }
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (102, 'f2239c54-0f29-4d49-9023-8de72cefe60f', '401', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-25 11:08:58.827364+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "easyspid104",
        "httpcode": 401,
        "message": "Invalid XML"
    },
    "id": "a24a87fd-363b-4070-8d18-4180a54b162f",
    "result": {
        "metadataValidate": {
            "certAllowed": true,
            "certValidity": true,
            "error": 0,
            "msg": "",
            "schemaValidate": false,
            "signCheck": true
        }
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (103, 'bba388d2-4769-4fd7-a1ea-848b5152b4dc', '401', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-25 11:10:10.745664+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "easyspid104",
        "httpcode": 401,
        "message": "Invalid XML"
    },
    "id": "350ab71f-9c0a-4dda-a4f2-e59896ebf302",
    "result": {
        "metadataValidate": {
            "certAllowed": true,
            "certValidity": true,
            "error": 0,
            "msg": "invalid_xml",
            "schemaValidate": false,
            "signCheck": true
        }
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (104, 'ea4dacc4-b2de-4850-9a43-e93c72211982', '200', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-25 11:12:54.548943+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "200",
        "httpcode": 200,
        "message": "OK"
    },
    "id": "c2c64627-233f-460d-8c54-89e84a18d84a",
    "result": {
        "metadataValidate": {
            "certAllowed": true,
            "certValidity": true,
            "error": 0,
            "msg": "",
            "schemaValidate": true,
            "signCheck": true
        }
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (105, '3f02b5b7-faee-419e-8d70-fbe585bbc154', '200', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-25 11:13:09.303923+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "200",
        "httpcode": 200,
        "message": "OK"
    },
    "id": "4c417870-5381-4a39-9edb-00ca90be4798",
    "result": {
        "metadataValidate": {
            "certAllowed": false,
            "certValidity": true,
            "error": 0,
            "msg": "",
            "schemaValidate": true,
            "signCheck": true
        }
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (106, '8d1704e7-d33c-4f3e-b885-b653a1c9a84b', '200', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-25 11:13:34.429824+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "200",
        "httpcode": 200,
        "message": "OK"
    },
    "id": "f0304dcd-a1e2-44e4-a583-0a693d519d40",
    "result": {
        "metadataValidate": {
            "certAllowed": true,
            "certValidity": true,
            "error": 0,
            "msg": "",
            "schemaValidate": true,
            "signCheck": true
        }
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (107, '85002951-88a9-454d-8cc4-945106e43b06', '200', 'http://192.168.56.103:8888/api/prvd/sapienza/metadata/build', '2017-07-25 11:13:52.004608+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "200",
        "httpcode": 200,
        "message": "OK"
    },
    "id": "8fecb93e-4b8e-40d6-9023-702c0fda1af6",
    "result": {
        "idassertion": null,
        "jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDA5NzUyMzEsImlhdCI6MTUwMDk3NDAzMSwiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6ImI1Njc3MDY3LWEzMzUtNGJiNi05ZDk4LTAwZmMwYzlhZjU3YSIsIm5iZiI6MTUwMDk3NDAzMSwic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.Gt2Jftdh1i-b0jG5R6j48wdyk_ovNUjKY5wBYZ3Dw_k",
        "metadata": "<md0:EntityDescriptor xmlns:md0=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:md1=\"urn:oasis:names:tc:SAML:2.0:assertion\" entityID=\"http://www.uniroma1.it\">\n    <md0:SPSSODescriptor AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n        <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n<ds:SignedInfo>\n<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n<ds:Reference>\n<ds:Transforms>\n<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n</ds:Transforms>\n<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n<ds:DigestValue>klrPVhpd8iPsKa5P2uMQ8sLFrTpxyJ2Ln4MIViP5dnw=</ds:DigestValue>\n</ds:Reference>\n</ds:SignedInfo>\n<ds:SignatureValue>ZkeT9oD/gSsHBfI6VJ8rcWM2RETXMBk7XoPmnmg5NTTrY8HK3fvjxCaGoPjpCBgY\nc8tIYc6+d9vXcz4BmIZc1uiWuROO+Wzbulvb4deu5ljiJau8sAgEPlbg2MNuAwA9\neFIYm+jwoP4ziRNwLywKqHKk1L12c4zXfnxzkhIgAP1touhl3c96aYVUNlhKd7Dz\n/C2p64jCCv2f1yGIKheAebsWv+OL8hrXchchFZXH1zndekssO5LL/EFZQx+KBR9b\ncP+xjB4+PSGS55QcKEQO4aOm3FDTckw+AbdR5bip7ufhSa0nXv9VZcVNpLQTGwwc\ntOlr1B5X407dRxmjLCVEE6ZlRWmHIU/K3XEhae5zO0pB2fFpSNC7/0mUeCT2ayGZ\nZp36XT8JGTsbW5tX0VcQLbBo+xlzrnrl1ymSbDBi5iI/S4uhycHzVPNR3a9KUBi5\nKiIwlWYuLdEHMexTAwa9/tsoriBwz5xNr+SRRJ2prJNjgQk7do/jcc1dkISaApVK\nFXNZhf1kv4/Yu5mmANxS0ZB+CaAogQRZbLsCkM2X+IfuF1Jf4P0ZZdeSRwVghyPr\neLfWKNP3YbGIDHRqXG9ZeVktAgjQ36vppMQ8z6CZCyY6VzgBRYUJUb9x5sqs5uR6\n3qrH7+UpAN8wTSVJnyQ3aVaVY/bozfXEEBBFLwdJCno=</ds:SignatureValue>\n<ds:KeyInfo>\n<ds:X509Data>\n<ds:X509Certificate>MIIGljCCBH6gAwIBAgIJAO2VpEv6m6DWMA0GCSqGSIb3DQEBDQUAMIHBMQswCQYD\nVQQGEwJJVDENMAsGA1UECBMEUm9tZTENMAsGA1UEBxMEUm9tZTEnMCUGA1UEChMe\nVW5pdmVyc2l0eSBvZiBSb21lIExhIFNhcGllbnphMTAwLgYDVQQLEydJbmZvU2Fw\naWVuemEsIFNldHRvcmUgQ2FycmllcmUgU3R1ZGVudGkxFDASBgNVBAMTC1N0dWRl\nbnRpIENBMSMwIQYJKoZIhvcNAQkBFhRpbmZvc3R1ZEB1bmlyb21hMS5pdDAeFw0x\nNzA1MTgxNjA0MjNaFw0xODA1MTgxNjA0MjNaMIGmMQswCQYDVQQGEwJJVDENMAsG\nA1UECBMEUm9tZTENMAsGA1UEBxMEUm9tZTEnMCUGA1UEChMeVW5pdmVyc2l0eSBv\nZiBSb21lIExhIFNhcGllbnphMREwDwYDVQQLEwhJbmZvc3R1ZDEYMBYGA1UEAxMP\nd3d3LnVuaXJvbWExLml0MSMwIQYJKoZIhvcNAQkBFhRpbmZvc3R1ZEB1bmlyb21h\nMS5pdDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMmP1yM0qycjfu/k\nmT0TqRbiPWMCi9uYAIu5U5twhY1WEJ8lzP4UTmtg5PRfkIcf5HgIiOF5BZCFp4n5\nOwcnFxXXzoJcIgMpmdcAM2ozyPPhxqQYvKOxM8jBjN6uioG6D40M5j5Qr5sneK9a\nkWOYsbQ8t4LmyML3jMZKK4kfmkgb5ccE4fgHUvXmdOb+t4/jNXqIXpzbXZslexTD\n91EJua8Kc3Ro4iV1+F0I/zv4BfXnAX+OOBWw3+toAnA1vF+/DCafaa/sr9yvQIho\njXVqcerYnLK/0u0dNdU9JpvD0bNXTJmXbVJakNClW0i7k929PclqC7XaRb7C2WW9\nxwD4BH95gTN0pDI6f5XDf8XwTg3KI9K3Ni7m/VhYm3WMHOlFqpSXd5x/7bbD94SY\nF3qo3bYqxIrynALqeQ61ASsxusktLFxUw6MyMrptwfPRLCqhWzzxyQYR2PVekS5C\nQunI6GhF/7pQaPJmLYJIL9TRSTPCROodmrfumIvOdu958qmDpOOXg4bWp1OWszah\n7AAqy4O5/ef0yUR+yI39wV9dxabo8TWV1HyFCpDVXyr6oNTmheL30pX2WQx1qATG\ndshpFIAU4zflKMxc0tRk0c47rBmTMsocrveIk4HrQDUX8o3i0T4bwc0Y/tCrp9ze\nt/hFsGPRPncOWRy44xZ18OjRLWjNAgMBAAGjgakwgaYwCQYDVR0TBAIwADAsBglg\nhkgBhvhCAQ0EHxYdT3BlblNTTCBHZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0O\nBBYEFBNMl6pIuv5bcO0KXUXPoCEEuIKkMB8GA1UdIwQYMBaAFB9i8gxKs7VGd5QM\nlTBXkF3ffvLrMCsGA1UdEgQkMCKGIGh0dHA6Ly8xOTIuMTY4LjEwLjE4MC9zc2wv\nY2EuY3J0MA0GCSqGSIb3DQEBDQUAA4ICAQBVJC2IgPAzs/skjA0tRxPCDNuGln6c\naWf1YMaUyMRfrrmvVZRpcdPdfpL6aJfF8NSTlz1CzFOW41J2cPUBVEe38OVGJmqB\n00rpBUMUB6TRdiHDhiLVlfS/EkVRZomM/KxuxZyi13vjqQBUpcdvmqqeI5QxX3rG\n+29i/BzoW4aTg27d1SFLF1GG+9KuIShk05epSzZ2F+ndZHSwJ9lGYh0RQM00q2Wo\nrN/kGc0BOwJTdFM/gWtumEZgixLtkBSia5M0z/JiePR7C5gaYY2db1DXMLodzQoJ\nTRu0VA9ibN9SBCPg9P2peYzWyk8acdEVB+3AKBNFmoKiIaHh84U3JCh/u3lrEC06\nkdX9sKmIM4WJiXIFFlvS44peUmjpb0hZWlz/GA+2EeWNYm0dBHef50R2f6PPWuRv\nl1GyNne0Z7/RGQPcrI9TUEG0Dw6HQriSmTQWOaoAU8KlomDH+ChC5kbI/H4D3L2Y\nMyPa5iFuNe4RCPL7071B57r0q2WsIw8sHVX8zm04msbRZV/dPwZ/0mscMfdjdQzL\nnpdO7ZYj0dcwaZNFLbrFKmGOmFBTj6ygj4/b6Bd4U222mtMMR4u+Lck6quWCkHcC\ngoQW9TCAnIbu//URPCyA+pivyvwG+vy295xIAeaQYBtWWXOIKZttmbLBcmfx4KaD\nA9j3h4a3EzHoPQ==</ds:X509Certificate>\n</ds:X509Data>\n</ds:KeyInfo>\n</ds:Signature><md0:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md0:KeyDescriptor><md0:KeyDescriptor use=\"encryption\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md0:KeyDescriptor><md0:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://www.uniroma1.it/spid/ssosignout\"/>\n        <md0:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md0:NameIDFormat>\n        <md0:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://www.uniroma1.it/spid/consume\" index=\"0\" isDefault=\"true\"/>\n        <md0:AttributeConsumingService index=\"0\">\n            <md0:ServiceName xml:lang=\"it\">Infostud</md0:ServiceName>\n            <md0:ServiceDescription xml:lang=\"it\">Infostud Login</md0:ServiceDescription>\n            <md0:RequestedAttribute FriendlyName=\"fefwe\" Name=\"fiscalNumber\" isRequired=\"true\">\n                <md1:AttributeValue>1</md1:AttributeValue>\n                <md1:AttributeValue>2</md1:AttributeValue>\n            </md0:RequestedAttribute>\n        </md0:AttributeConsumingService>\n    </md0:SPSSODescriptor>\n    <md0:Organization>\n        <md0:OrganizationName xml:lang=\"it\">Universita'' Sapienza</md0:OrganizationName>\n        <md0:OrganizationDisplayName xml:lang=\"it\">Universita'' degli Studi La Sapienza - Roma</md0:OrganizationDisplayName>\n        <md0:OrganizationURL xml:lang=\"it\">http://www.uniroma1.it</md0:OrganizationURL>\n    </md0:Organization>\n    <md0:ContactPerson contactType=\"support\">\n        <md0:GivenName>InfoSapienza</md0:GivenName>\n        <md0:EmailAddress>infostud@uniroma1.it</md0:EmailAddress>\n    </md0:ContactPerson>\n    <md0:ContactPerson contactType=\"technical\">\n        <md0:GivenName>InfoSapienza</md0:GivenName>\n        <md0:EmailAddress>infostud@uniroma1.it</md0:EmailAddress>\n    </md0:ContactPerson>\n</md0:EntityDescriptor>"
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (108, '6b14fadb-220c-4b88-9a33-8c8650c9c75a', '200', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-25 11:14:34.67878+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "200",
        "httpcode": 200,
        "message": "OK"
    },
    "id": "460eeea4-7ddb-4dc5-b4f3-c058657fc7ce",
    "result": {
        "metadataValidate": {
            "certAllowed": false,
            "certValidity": true,
            "error": 0,
            "msg": "",
            "schemaValidate": true,
            "signCheck": true
        }
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (109, '69019057-aae7-4193-96f0-fb9b54b57618', '200', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-25 11:14:42.890702+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "200",
        "httpcode": 200,
        "message": "OK"
    },
    "id": "dae14a9f-bddf-4fcd-9c95-6ba3808cb889",
    "result": {
        "metadataValidate": {
            "certAllowed": false,
            "certValidity": true,
            "error": 0,
            "msg": "",
            "schemaValidate": true,
            "signCheck": true
        }
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (110, 'd3201255-8c09-4495-b1e3-745dea71e773', '200', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-25 11:14:51.346188+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "200",
        "httpcode": 200,
        "message": "OK"
    },
    "id": "ff071a90-9439-42e4-9e75-d3eef3fecaa8",
    "result": {
        "metadataValidate": {
            "certAllowed": true,
            "certValidity": true,
            "error": 0,
            "msg": "",
            "schemaValidate": true,
            "signCheck": true
        }
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (111, '5a8a8b3e-3f13-40b5-93e2-aa6625475552', '200', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-25 11:14:57.013786+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "200",
        "httpcode": 200,
        "message": "OK"
    },
    "id": "5bd145c1-df02-4a34-b803-717d71445ec1",
    "result": {
        "metadataValidate": {
            "certAllowed": true,
            "certValidity": true,
            "error": 0,
            "msg": "",
            "schemaValidate": true,
            "signCheck": true
        }
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (112, '8c398f4e-b43e-4638-a1c3-1c179ff425b7', '200', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-25 11:15:41.529737+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "200",
        "httpcode": 200,
        "message": "OK"
    },
    "id": "9baed469-69c7-4603-8b69-254dd22ba2e9",
    "result": {
        "metadataValidate": {
            "certAllowed": false,
            "certValidity": false,
            "error": 0,
            "msg": "",
            "schemaValidate": true,
            "signCheck": true
        }
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (113, '0b2aeb93-9e4a-481e-bcb0-26231ee9bea6', '200', 'http://192.168.56.103:8888/api/prvd/sapienza/authnreq/build?idp=pt&attrindex=0&binding=redirect', '2017-07-25 11:16:10.622776+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "200",
        "httpcode": 200,
        "message": "OK"
    },
    "id": "ONELOGIN_18c0544b42bb91769fe826093cfaf21ce62134e6",
    "result": {
        "authnrequest": "<ns0:AuthnRequest xmlns:md1=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:ns0=\"urn:oasis:names:tc:SAML:2.0:protocol\" AssertionConsumerServiceURL=\"http://www.uniroma1.it/spid/consume\" AttributeConsumingServiceIndex=\"0\" Destination=\"https://posteid.poste.it/jod-fs/ssoserviceredirect\" ForceAuthn=\"true\" ID=\"ONELOGIN_18c0544b42bb91769fe826093cfaf21ce62134e6\" IssueInstant=\"2017-07-25T09:16:10Z\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" ProviderName=\"Universita'' degli Studi La Sapienza - Roma\" Version=\"2.0\">\n    <md1:Issuer Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\" NameQualifier=\"http://www.uniroma1.it\">http://www.uniroma1.it</md1:Issuer><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n<ds:SignedInfo>\n<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n<ds:Reference URI=\"#ONELOGIN_18c0544b42bb91769fe826093cfaf21ce62134e6\">\n<ds:Transforms>\n<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n</ds:Transforms>\n<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n<ds:DigestValue>MapCNSCalr0jgd58Dt+Arn5A7SJVVJW6txjUmwXY+Os=</ds:DigestValue>\n</ds:Reference>\n</ds:SignedInfo>\n<ds:SignatureValue>VIYGHq82Abrzwoor/wcfIHiGV6v9WVsf4YVrU9fZU8Xd1rK09QTJfTDaUDn+t0zc\n1kkZxS1cvnW4BuMIFVtUa25MWfByq8uc2AvZUctaXNkFyuCyK6HEkJPHB2WULx9D\nlS1VLl+aUhLEMheOxKP+3byhga1ArilRxcx/MRCvjWISFjHGeeFII2ceJFrzgQck\n+OBLbYvBcOVPLLEnLPOd050Vh+OHzzTahPc/CDmsIyeTA2Ok9xS+2B4kszhpBiw/\nPHnAMhjPA4TP+PuCfehszsLqJ4hYexHL9fsJ1w/HPXGXg/QfeXGS02Xst+bf0Xw6\niDVrcyQuC5icH/NFHbrQJeC/pOg23MDvXgx4Nv0+Y8YU6FMb9uB4Fyfdul5RVQUd\nUoIXzQ71OMB4nVtBb2X61QtDxR/RYyCWe+8+gmh0WUU0HCni80T0GR/cP09pYCvw\nusXtDZUfAPAOJ7a+0VKMfR609KLLvIPRsI60kdNiAxFVWZ4W9CRqooFCctqPPjQC\nS2zbJocJzz/4m/cQp6FWpgYYziU2RO+gdxK/AmFQJmhA3tKD04jqAI9dCZp9xatt\nFWDbcnJsLvU+4Ol+vQQ/vDiD5e+nFV+QEHKICtPiOcICQcUwmXbjjMWpX46s0GpN\n/Z0h7ux15mEHZ9dAU1XYRPtMAxneBCaijd6DHuJNT08=</ds:SignatureValue>\n<ds:KeyInfo>\n<ds:X509Data>\n<ds:X509Certificate>MIIGljCCBH6gAwIBAgIJAO2VpEv6m6DWMA0GCSqGSIb3DQEBDQUAMIHBMQswCQYD\nVQQGEwJJVDENMAsGA1UECBMEUm9tZTENMAsGA1UEBxMEUm9tZTEnMCUGA1UEChMe\nVW5pdmVyc2l0eSBvZiBSb21lIExhIFNhcGllbnphMTAwLgYDVQQLEydJbmZvU2Fw\naWVuemEsIFNldHRvcmUgQ2FycmllcmUgU3R1ZGVudGkxFDASBgNVBAMTC1N0dWRl\nbnRpIENBMSMwIQYJKoZIhvcNAQkBFhRpbmZvc3R1ZEB1bmlyb21hMS5pdDAeFw0x\nNzA1MTgxNjA0MjNaFw0xODA1MTgxNjA0MjNaMIGmMQswCQYDVQQGEwJJVDENMAsG\nA1UECBMEUm9tZTENMAsGA1UEBxMEUm9tZTEnMCUGA1UEChMeVW5pdmVyc2l0eSBv\nZiBSb21lIExhIFNhcGllbnphMREwDwYDVQQLEwhJbmZvc3R1ZDEYMBYGA1UEAxMP\nd3d3LnVuaXJvbWExLml0MSMwIQYJKoZIhvcNAQkBFhRpbmZvc3R1ZEB1bmlyb21h\nMS5pdDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMmP1yM0qycjfu/k\nmT0TqRbiPWMCi9uYAIu5U5twhY1WEJ8lzP4UTmtg5PRfkIcf5HgIiOF5BZCFp4n5\nOwcnFxXXzoJcIgMpmdcAM2ozyPPhxqQYvKOxM8jBjN6uioG6D40M5j5Qr5sneK9a\nkWOYsbQ8t4LmyML3jMZKK4kfmkgb5ccE4fgHUvXmdOb+t4/jNXqIXpzbXZslexTD\n91EJua8Kc3Ro4iV1+F0I/zv4BfXnAX+OOBWw3+toAnA1vF+/DCafaa/sr9yvQIho\njXVqcerYnLK/0u0dNdU9JpvD0bNXTJmXbVJakNClW0i7k929PclqC7XaRb7C2WW9\nxwD4BH95gTN0pDI6f5XDf8XwTg3KI9K3Ni7m/VhYm3WMHOlFqpSXd5x/7bbD94SY\nF3qo3bYqxIrynALqeQ61ASsxusktLFxUw6MyMrptwfPRLCqhWzzxyQYR2PVekS5C\nQunI6GhF/7pQaPJmLYJIL9TRSTPCROodmrfumIvOdu958qmDpOOXg4bWp1OWszah\n7AAqy4O5/ef0yUR+yI39wV9dxabo8TWV1HyFCpDVXyr6oNTmheL30pX2WQx1qATG\ndshpFIAU4zflKMxc0tRk0c47rBmTMsocrveIk4HrQDUX8o3i0T4bwc0Y/tCrp9ze\nt/hFsGPRPncOWRy44xZ18OjRLWjNAgMBAAGjgakwgaYwCQYDVR0TBAIwADAsBglg\nhkgBhvhCAQ0EHxYdT3BlblNTTCBHZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0O\nBBYEFBNMl6pIuv5bcO0KXUXPoCEEuIKkMB8GA1UdIwQYMBaAFB9i8gxKs7VGd5QM\nlTBXkF3ffvLrMCsGA1UdEgQkMCKGIGh0dHA6Ly8xOTIuMTY4LjEwLjE4MC9zc2wv\nY2EuY3J0MA0GCSqGSIb3DQEBDQUAA4ICAQBVJC2IgPAzs/skjA0tRxPCDNuGln6c\naWf1YMaUyMRfrrmvVZRpcdPdfpL6aJfF8NSTlz1CzFOW41J2cPUBVEe38OVGJmqB\n00rpBUMUB6TRdiHDhiLVlfS/EkVRZomM/KxuxZyi13vjqQBUpcdvmqqeI5QxX3rG\n+29i/BzoW4aTg27d1SFLF1GG+9KuIShk05epSzZ2F+ndZHSwJ9lGYh0RQM00q2Wo\nrN/kGc0BOwJTdFM/gWtumEZgixLtkBSia5M0z/JiePR7C5gaYY2db1DXMLodzQoJ\nTRu0VA9ibN9SBCPg9P2peYzWyk8acdEVB+3AKBNFmoKiIaHh84U3JCh/u3lrEC06\nkdX9sKmIM4WJiXIFFlvS44peUmjpb0hZWlz/GA+2EeWNYm0dBHef50R2f6PPWuRv\nl1GyNne0Z7/RGQPcrI9TUEG0Dw6HQriSmTQWOaoAU8KlomDH+ChC5kbI/H4D3L2Y\nMyPa5iFuNe4RCPL7071B57r0q2WsIw8sHVX8zm04msbRZV/dPwZ/0mscMfdjdQzL\nnpdO7ZYj0dcwaZNFLbrFKmGOmFBTj6ygj4/b6Bd4U222mtMMR4u+Lck6quWCkHcC\ngoQW9TCAnIbu//URPCyA+pivyvwG+vy295xIAeaQYBtWWXOIKZttmbLBcmfx4KaD\nA9j3h4a3EzHoPQ==</ds:X509Certificate>\n</ds:X509Data>\n</ds:KeyInfo>\n</ds:Signature>\n    <ns0:NameIDPolicy AllowCreate=\"true\" Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\"/>\n     <ns0:RequestedAuthnContext Comparison=\"minimum\"><md1:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:SpidL1</md1:AuthnContextClassRef>    </ns0:RequestedAuthnContext>\n</ns0:AuthnRequest>",
        "idassertion": "ONELOGIN_18c0544b42bb91769fe826093cfaf21ce62134e6",
        "jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJTZXJ2aWNlIFByb3ZpZGVycyB1c2luZyBFYXN5U1BJRCBBUEkiLCJleHAiOjE1MDA5NzUzNzEsImlhdCI6MTUwMDk3NDE3MSwiaXNzIjoiRWFzeVNQSUQgZ2F0ZXdheSIsImp0aSI6IjQzYjg1MzNmLWViZDYtNDVkNC04MmJhLTUyNzBjMThiMDJkNyIsIm5iZiI6MTUwMDk3NDE3MSwic3ViIjoiQWNjZXNzIHRvIEVhc3lTUElEIEFQSSJ9.VCMwYRtWei9ARabk0qMbzyn_zSP_XEocEcBuaHw9Enc"
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (114, 'd41ce8a4-578a-4259-8ec0-1c707ba4f9d3', '200', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-25 11:16:41.042801+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "200",
        "httpcode": 200,
        "message": "OK"
    },
    "id": "0482d347-1323-4d7e-abc4-e0735879c904",
    "result": {
        "metadataValidate": {
            "certAllowed": true,
            "certValidity": true,
            "error": 0,
            "msg": "",
            "schemaValidate": true,
            "signCheck": true
        }
    }
}');
INSERT INTO responses ("ID", cod_response, http_code, url_origin, date, client, response) VALUES (115, 'cf779c63-90ee-40ee-8bbd-1e3578fcf108', '200', 'http://192.168.56.103:8888/api/assertion/validate', '2017-07-25 11:16:49.451366+02', '192.168.56.1', '{
    "apiVersion": "1.3",
    "error": {
        "code": "200",
        "httpcode": 200,
        "message": "OK"
    },
    "id": "2938bf7b-293e-430f-8f09-6d376dd42b55",
    "result": {
        "metadataValidate": {
            "certAllowed": false,
            "certValidity": true,
            "error": 0,
            "msg": "",
            "schemaValidate": true,
            "signCheck": true
        }
    }
}');


SET search_path = saml, pg_catalog;

--
-- TOC entry 2810 (class 0 OID 33876)
-- Dependencies: 208
-- Data for Name: assertions; Type: TABLE DATA; Schema: saml; Owner: easyspid
--

INSERT INTO assertions ("ID", cod_assertion, assertion, cod_token, cod_type, date, "ID_assertion", cod_sp, cod_idp, client, "ID_response_assertion") VALUES (3255, 'e7ee8645-f155-4c56-b760-c96a5819000d', '<md0:EntityDescriptor xmlns:md0="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:md1="urn:oasis:names:tc:SAML:2.0:assertion" entityID="http://www.uniroma1.it">
    <md0:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
<ds:Reference>
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
<ds:DigestValue>klrPVhpd8iPsKa5P2uMQ8sLFrTpxyJ2Ln4MIViP5dnw=</ds:DigestValue>
</ds:Reference>
</ds:SignedInfo>
<ds:SignatureValue>ZkeT9oD/gSsHBfI6VJ8rcWM2RETXMBk7XoPmnmg5NTTrY8HK3fvjxCaGoPjpCBgY
c8tIYc6+d9vXcz4BmIZc1uiWuROO+Wzbulvb4deu5ljiJau8sAgEPlbg2MNuAwA9
eFIYm+jwoP4ziRNwLywKqHKk1L12c4zXfnxzkhIgAP1touhl3c96aYVUNlhKd7Dz
/C2p64jCCv2f1yGIKheAebsWv+OL8hrXchchFZXH1zndekssO5LL/EFZQx+KBR9b
cP+xjB4+PSGS55QcKEQO4aOm3FDTckw+AbdR5bip7ufhSa0nXv9VZcVNpLQTGwwc
tOlr1B5X407dRxmjLCVEE6ZlRWmHIU/K3XEhae5zO0pB2fFpSNC7/0mUeCT2ayGZ
Zp36XT8JGTsbW5tX0VcQLbBo+xlzrnrl1ymSbDBi5iI/S4uhycHzVPNR3a9KUBi5
KiIwlWYuLdEHMexTAwa9/tsoriBwz5xNr+SRRJ2prJNjgQk7do/jcc1dkISaApVK
FXNZhf1kv4/Yu5mmANxS0ZB+CaAogQRZbLsCkM2X+IfuF1Jf4P0ZZdeSRwVghyPr
eLfWKNP3YbGIDHRqXG9ZeVktAgjQ36vppMQ8z6CZCyY6VzgBRYUJUb9x5sqs5uR6
3qrH7+UpAN8wTSVJnyQ3aVaVY/bozfXEEBBFLwdJCno=</ds:SignatureValue>
<ds:KeyInfo>
<ds:X509Data>
<ds:X509Certificate>MIIGljCCBH6gAwIBAgIJAO2VpEv6m6DWMA0GCSqGSIb3DQEBDQUAMIHBMQswCQYD
VQQGEwJJVDENMAsGA1UECBMEUm9tZTENMAsGA1UEBxMEUm9tZTEnMCUGA1UEChMe
VW5pdmVyc2l0eSBvZiBSb21lIExhIFNhcGllbnphMTAwLgYDVQQLEydJbmZvU2Fw
aWVuemEsIFNldHRvcmUgQ2FycmllcmUgU3R1ZGVudGkxFDASBgNVBAMTC1N0dWRl
bnRpIENBMSMwIQYJKoZIhvcNAQkBFhRpbmZvc3R1ZEB1bmlyb21hMS5pdDAeFw0x
NzA1MTgxNjA0MjNaFw0xODA1MTgxNjA0MjNaMIGmMQswCQYDVQQGEwJJVDENMAsG
A1UECBMEUm9tZTENMAsGA1UEBxMEUm9tZTEnMCUGA1UEChMeVW5pdmVyc2l0eSBv
ZiBSb21lIExhIFNhcGllbnphMREwDwYDVQQLEwhJbmZvc3R1ZDEYMBYGA1UEAxMP
d3d3LnVuaXJvbWExLml0MSMwIQYJKoZIhvcNAQkBFhRpbmZvc3R1ZEB1bmlyb21h
MS5pdDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMmP1yM0qycjfu/k
mT0TqRbiPWMCi9uYAIu5U5twhY1WEJ8lzP4UTmtg5PRfkIcf5HgIiOF5BZCFp4n5
OwcnFxXXzoJcIgMpmdcAM2ozyPPhxqQYvKOxM8jBjN6uioG6D40M5j5Qr5sneK9a
kWOYsbQ8t4LmyML3jMZKK4kfmkgb5ccE4fgHUvXmdOb+t4/jNXqIXpzbXZslexTD
91EJua8Kc3Ro4iV1+F0I/zv4BfXnAX+OOBWw3+toAnA1vF+/DCafaa/sr9yvQIho
jXVqcerYnLK/0u0dNdU9JpvD0bNXTJmXbVJakNClW0i7k929PclqC7XaRb7C2WW9
xwD4BH95gTN0pDI6f5XDf8XwTg3KI9K3Ni7m/VhYm3WMHOlFqpSXd5x/7bbD94SY
F3qo3bYqxIrynALqeQ61ASsxusktLFxUw6MyMrptwfPRLCqhWzzxyQYR2PVekS5C
QunI6GhF/7pQaPJmLYJIL9TRSTPCROodmrfumIvOdu958qmDpOOXg4bWp1OWszah
7AAqy4O5/ef0yUR+yI39wV9dxabo8TWV1HyFCpDVXyr6oNTmheL30pX2WQx1qATG
dshpFIAU4zflKMxc0tRk0c47rBmTMsocrveIk4HrQDUX8o3i0T4bwc0Y/tCrp9ze
t/hFsGPRPncOWRy44xZ18OjRLWjNAgMBAAGjgakwgaYwCQYDVR0TBAIwADAsBglg
hkgBhvhCAQ0EHxYdT3BlblNTTCBHZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0O
BBYEFBNMl6pIuv5bcO0KXUXPoCEEuIKkMB8GA1UdIwQYMBaAFB9i8gxKs7VGd5QM
lTBXkF3ffvLrMCsGA1UdEgQkMCKGIGh0dHA6Ly8xOTIuMTY4LjEwLjE4MC9zc2wv
Y2EuY3J0MA0GCSqGSIb3DQEBDQUAA4ICAQBVJC2IgPAzs/skjA0tRxPCDNuGln6c
aWf1YMaUyMRfrrmvVZRpcdPdfpL6aJfF8NSTlz1CzFOW41J2cPUBVEe38OVGJmqB
00rpBUMUB6TRdiHDhiLVlfS/EkVRZomM/KxuxZyi13vjqQBUpcdvmqqeI5QxX3rG
+29i/BzoW4aTg27d1SFLF1GG+9KuIShk05epSzZ2F+ndZHSwJ9lGYh0RQM00q2Wo
rN/kGc0BOwJTdFM/gWtumEZgixLtkBSia5M0z/JiePR7C5gaYY2db1DXMLodzQoJ
TRu0VA9ibN9SBCPg9P2peYzWyk8acdEVB+3AKBNFmoKiIaHh84U3JCh/u3lrEC06
kdX9sKmIM4WJiXIFFlvS44peUmjpb0hZWlz/GA+2EeWNYm0dBHef50R2f6PPWuRv
l1GyNne0Z7/RGQPcrI9TUEG0Dw6HQriSmTQWOaoAU8KlomDH+ChC5kbI/H4D3L2Y
MyPa5iFuNe4RCPL7071B57r0q2WsIw8sHVX8zm04msbRZV/dPwZ/0mscMfdjdQzL
npdO7ZYj0dcwaZNFLbrFKmGOmFBTj6ygj4/b6Bd4U222mtMMR4u+Lck6quWCkHcC
goQW9TCAnIbu//URPCyA+pivyvwG+vy295xIAeaQYBtWWXOIKZttmbLBcmfx4KaD
A9j3h4a3EzHoPQ==</ds:X509Certificate>
</ds:X509Data>
</ds:KeyInfo>
</ds:Signature><md0:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md0:KeyDescriptor><md0:KeyDescriptor use="encryption"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md0:KeyDescriptor><md0:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://www.uniroma1.it/spid/ssosignout"/>
        <md0:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md0:NameIDFormat>
        <md0:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://www.uniroma1.it/spid/consume" index="0" isDefault="true"/>
        <md0:AttributeConsumingService index="0">
            <md0:ServiceName xml:lang="it">Infostud</md0:ServiceName>
            <md0:ServiceDescription xml:lang="it">Infostud Login</md0:ServiceDescription>
            <md0:RequestedAttribute FriendlyName="fefwe" Name="fiscalNumber" isRequired="true">
                <md1:AttributeValue>1</md1:AttributeValue>
                <md1:AttributeValue>2</md1:AttributeValue>
            </md0:RequestedAttribute>
        </md0:AttributeConsumingService>
    </md0:SPSSODescriptor>
    <md0:Organization>
        <md0:OrganizationName xml:lang="it">Universita'' Sapienza</md0:OrganizationName>
        <md0:OrganizationDisplayName xml:lang="it">Universita'' degli Studi La Sapienza - Roma</md0:OrganizationDisplayName>
        <md0:OrganizationURL xml:lang="it">http://www.uniroma1.it</md0:OrganizationURL>
    </md0:Organization>
    <md0:ContactPerson contactType="support">
        <md0:GivenName>InfoSapienza</md0:GivenName>
        <md0:EmailAddress>infostud@uniroma1.it</md0:EmailAddress>
    </md0:ContactPerson>
    <md0:ContactPerson contactType="technical">
        <md0:GivenName>InfoSapienza</md0:GivenName>
        <md0:EmailAddress>infostud@uniroma1.it</md0:EmailAddress>
    </md0:ContactPerson>
</md0:EntityDescriptor>', 'b5677067-a335-4bb6-9d98-00fc0c9af57a', 'EntityDescriptor', '2017-07-25 11:13:51.457232+02', NULL, 'sapienza', NULL, '192.168.56.1', NULL);
INSERT INTO assertions ("ID", cod_assertion, assertion, cod_token, cod_type, date, "ID_assertion", cod_sp, cod_idp, client, "ID_response_assertion") VALUES (3256, '4030d100-a12f-4175-9b8c-4b354eaa7da8', '<ns0:AuthnRequest xmlns:md1="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ns0="urn:oasis:names:tc:SAML:2.0:protocol" AssertionConsumerServiceURL="http://www.uniroma1.it/spid/consume" AttributeConsumingServiceIndex="0" Destination="https://posteid.poste.it/jod-fs/ssoserviceredirect" ForceAuthn="true" ID="ONELOGIN_18c0544b42bb91769fe826093cfaf21ce62134e6" IssueInstant="2017-07-25T09:16:10Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ProviderName="Universita'' degli Studi La Sapienza - Roma" Version="2.0">
    <md1:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" NameQualifier="http://www.uniroma1.it">http://www.uniroma1.it</md1:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
<ds:Reference URI="#ONELOGIN_18c0544b42bb91769fe826093cfaf21ce62134e6">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
<ds:DigestValue>MapCNSCalr0jgd58Dt+Arn5A7SJVVJW6txjUmwXY+Os=</ds:DigestValue>
</ds:Reference>
</ds:SignedInfo>
<ds:SignatureValue>VIYGHq82Abrzwoor/wcfIHiGV6v9WVsf4YVrU9fZU8Xd1rK09QTJfTDaUDn+t0zc
1kkZxS1cvnW4BuMIFVtUa25MWfByq8uc2AvZUctaXNkFyuCyK6HEkJPHB2WULx9D
lS1VLl+aUhLEMheOxKP+3byhga1ArilRxcx/MRCvjWISFjHGeeFII2ceJFrzgQck
+OBLbYvBcOVPLLEnLPOd050Vh+OHzzTahPc/CDmsIyeTA2Ok9xS+2B4kszhpBiw/
PHnAMhjPA4TP+PuCfehszsLqJ4hYexHL9fsJ1w/HPXGXg/QfeXGS02Xst+bf0Xw6
iDVrcyQuC5icH/NFHbrQJeC/pOg23MDvXgx4Nv0+Y8YU6FMb9uB4Fyfdul5RVQUd
UoIXzQ71OMB4nVtBb2X61QtDxR/RYyCWe+8+gmh0WUU0HCni80T0GR/cP09pYCvw
usXtDZUfAPAOJ7a+0VKMfR609KLLvIPRsI60kdNiAxFVWZ4W9CRqooFCctqPPjQC
S2zbJocJzz/4m/cQp6FWpgYYziU2RO+gdxK/AmFQJmhA3tKD04jqAI9dCZp9xatt
FWDbcnJsLvU+4Ol+vQQ/vDiD5e+nFV+QEHKICtPiOcICQcUwmXbjjMWpX46s0GpN
/Z0h7ux15mEHZ9dAU1XYRPtMAxneBCaijd6DHuJNT08=</ds:SignatureValue>
<ds:KeyInfo>
<ds:X509Data>
<ds:X509Certificate>MIIGljCCBH6gAwIBAgIJAO2VpEv6m6DWMA0GCSqGSIb3DQEBDQUAMIHBMQswCQYD
VQQGEwJJVDENMAsGA1UECBMEUm9tZTENMAsGA1UEBxMEUm9tZTEnMCUGA1UEChMe
VW5pdmVyc2l0eSBvZiBSb21lIExhIFNhcGllbnphMTAwLgYDVQQLEydJbmZvU2Fw
aWVuemEsIFNldHRvcmUgQ2FycmllcmUgU3R1ZGVudGkxFDASBgNVBAMTC1N0dWRl
bnRpIENBMSMwIQYJKoZIhvcNAQkBFhRpbmZvc3R1ZEB1bmlyb21hMS5pdDAeFw0x
NzA1MTgxNjA0MjNaFw0xODA1MTgxNjA0MjNaMIGmMQswCQYDVQQGEwJJVDENMAsG
A1UECBMEUm9tZTENMAsGA1UEBxMEUm9tZTEnMCUGA1UEChMeVW5pdmVyc2l0eSBv
ZiBSb21lIExhIFNhcGllbnphMREwDwYDVQQLEwhJbmZvc3R1ZDEYMBYGA1UEAxMP
d3d3LnVuaXJvbWExLml0MSMwIQYJKoZIhvcNAQkBFhRpbmZvc3R1ZEB1bmlyb21h
MS5pdDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMmP1yM0qycjfu/k
mT0TqRbiPWMCi9uYAIu5U5twhY1WEJ8lzP4UTmtg5PRfkIcf5HgIiOF5BZCFp4n5
OwcnFxXXzoJcIgMpmdcAM2ozyPPhxqQYvKOxM8jBjN6uioG6D40M5j5Qr5sneK9a
kWOYsbQ8t4LmyML3jMZKK4kfmkgb5ccE4fgHUvXmdOb+t4/jNXqIXpzbXZslexTD
91EJua8Kc3Ro4iV1+F0I/zv4BfXnAX+OOBWw3+toAnA1vF+/DCafaa/sr9yvQIho
jXVqcerYnLK/0u0dNdU9JpvD0bNXTJmXbVJakNClW0i7k929PclqC7XaRb7C2WW9
xwD4BH95gTN0pDI6f5XDf8XwTg3KI9K3Ni7m/VhYm3WMHOlFqpSXd5x/7bbD94SY
F3qo3bYqxIrynALqeQ61ASsxusktLFxUw6MyMrptwfPRLCqhWzzxyQYR2PVekS5C
QunI6GhF/7pQaPJmLYJIL9TRSTPCROodmrfumIvOdu958qmDpOOXg4bWp1OWszah
7AAqy4O5/ef0yUR+yI39wV9dxabo8TWV1HyFCpDVXyr6oNTmheL30pX2WQx1qATG
dshpFIAU4zflKMxc0tRk0c47rBmTMsocrveIk4HrQDUX8o3i0T4bwc0Y/tCrp9ze
t/hFsGPRPncOWRy44xZ18OjRLWjNAgMBAAGjgakwgaYwCQYDVR0TBAIwADAsBglg
hkgBhvhCAQ0EHxYdT3BlblNTTCBHZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0O
BBYEFBNMl6pIuv5bcO0KXUXPoCEEuIKkMB8GA1UdIwQYMBaAFB9i8gxKs7VGd5QM
lTBXkF3ffvLrMCsGA1UdEgQkMCKGIGh0dHA6Ly8xOTIuMTY4LjEwLjE4MC9zc2wv
Y2EuY3J0MA0GCSqGSIb3DQEBDQUAA4ICAQBVJC2IgPAzs/skjA0tRxPCDNuGln6c
aWf1YMaUyMRfrrmvVZRpcdPdfpL6aJfF8NSTlz1CzFOW41J2cPUBVEe38OVGJmqB
00rpBUMUB6TRdiHDhiLVlfS/EkVRZomM/KxuxZyi13vjqQBUpcdvmqqeI5QxX3rG
+29i/BzoW4aTg27d1SFLF1GG+9KuIShk05epSzZ2F+ndZHSwJ9lGYh0RQM00q2Wo
rN/kGc0BOwJTdFM/gWtumEZgixLtkBSia5M0z/JiePR7C5gaYY2db1DXMLodzQoJ
TRu0VA9ibN9SBCPg9P2peYzWyk8acdEVB+3AKBNFmoKiIaHh84U3JCh/u3lrEC06
kdX9sKmIM4WJiXIFFlvS44peUmjpb0hZWlz/GA+2EeWNYm0dBHef50R2f6PPWuRv
l1GyNne0Z7/RGQPcrI9TUEG0Dw6HQriSmTQWOaoAU8KlomDH+ChC5kbI/H4D3L2Y
MyPa5iFuNe4RCPL7071B57r0q2WsIw8sHVX8zm04msbRZV/dPwZ/0mscMfdjdQzL
npdO7ZYj0dcwaZNFLbrFKmGOmFBTj6ygj4/b6Bd4U222mtMMR4u+Lck6quWCkHcC
goQW9TCAnIbu//URPCyA+pivyvwG+vy295xIAeaQYBtWWXOIKZttmbLBcmfx4KaD
A9j3h4a3EzHoPQ==</ds:X509Certificate>
</ds:X509Data>
</ds:KeyInfo>
</ds:Signature>
    <ns0:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"/>
     <ns0:RequestedAuthnContext Comparison="minimum"><md1:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:SpidL1</md1:AuthnContextClassRef>    </ns0:RequestedAuthnContext>
</ns0:AuthnRequest>', '43b8533f-ebd6-45d4-82ba-5270c18b02d7', 'AuthnRequest', '2017-07-25 11:16:10.603616+02', 'ONELOGIN_18c0544b42bb91769fe826093cfaf21ce62134e6', 'sapienza', 'pt', '192.168.56.1', NULL);


--
-- TOC entry 2866 (class 0 OID 0)
-- Dependencies: 207
-- Name: assertions_ID_seq; Type: SEQUENCE SET; Schema: saml; Owner: easyspid
--

SELECT pg_catalog.setval('"assertions_ID_seq"', 3256, true);


--
-- TOC entry 2812 (class 0 OID 33968)
-- Dependencies: 210
-- Data for Name: assertions_type; Type: TABLE DATA; Schema: saml; Owner: easyspid
--

INSERT INTO assertions_type ("ID", cod_type, type) VALUES (2, 'AuthnRequest', 'Saml Request');
INSERT INTO assertions_type ("ID", cod_type, type) VALUES (4, 'EntityDescriptor', 'Saml Metadata');
INSERT INTO assertions_type ("ID", cod_type, type) VALUES (1, 'Response', 'Saml Response');


--
-- TOC entry 2867 (class 0 OID 0)
-- Dependencies: 209
-- Name: assertions_type_ID_seq; Type: SEQUENCE SET; Schema: saml; Owner: easyspid
--

SELECT pg_catalog.setval('"assertions_type_ID_seq"', 4, true);


--
-- TOC entry 2868 (class 0 OID 0)
-- Dependencies: 205
-- Name: certifcates_ID_seq; Type: SEQUENCE SET; Schema: saml; Owner: easyspid
--

SELECT pg_catalog.setval('"certifcates_ID_seq"', 12, true);


--
-- TOC entry 2820 (class 0 OID 42292)
-- Dependencies: 218
-- Data for Name: jwt_settings; Type: TABLE DATA; Schema: saml; Owner: easyspid
--

INSERT INTO jwt_settings ("ID", cod_jwt_setting, cod_provider, cod_type_assertion, cod_type_token) VALUES (2, '5d6f4883-2c26-4489-a82c-42b0567624b8', 'sapienza', 'AuthnRequest', 'jwt1');
INSERT INTO jwt_settings ("ID", cod_jwt_setting, cod_provider, cod_type_assertion, cod_type_token) VALUES (5, '8cb70e43-06b7-4461-b14c-9a116bf3f7b1', 'sapienza', 'EntityDescriptor', 'jwt1');
INSERT INTO jwt_settings ("ID", cod_jwt_setting, cod_provider, cod_type_assertion, cod_type_token) VALUES (6, '76e7d3df-35b9-434d-97ff-97003bef32c7', 'sapienza', 'Response', 'jwt1');


--
-- TOC entry 2869 (class 0 OID 0)
-- Dependencies: 217
-- Name: jwt_settings_ID_seq; Type: SEQUENCE SET; Schema: saml; Owner: easyspid
--

SELECT pg_catalog.setval('"jwt_settings_ID_seq"', 6, true);


--
-- TOC entry 2816 (class 0 OID 34628)
-- Dependencies: 214
-- Data for Name: metadata; Type: TABLE DATA; Schema: saml; Owner: easyspid
--

INSERT INTO metadata ("ID", cod_metadata, xml, date, note, active, cod_provider) VALUES (3, 'infocert_meta', '<?xml version="1.0" standalone="no"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ID="_25b183c4c721960977003fb04ec600b4" cacheDuration="P0Y0M30DT0H0M0.000S" entityID="https://identity.infocert.it"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#_25b183c4c721960977003fb04ec600b4"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>hKbiiLWanDYNT69FQLh4uWlI6rVdAfoNXltq8WE83No=</DigestValue></Reference></SignedInfo><SignatureValue>nqWCyBqw40iHn3OEF9qVnJIzX9xmTzoq3EE9pbpPtrrAnjBWKTI2GxCAH84oD7BArJ/oBWOEQ0iJzFLwdtJK56ly8MwFAiYdCuNm9wHd03gSGBMxaWbhQSfwkwRCmMbzxcXJGMhh4JECOdZ87KR861A+S2EPyWBHC9yx8iRZ4UtmrGpf3UWyFJsCEjCLZv+a/ld6WnkP43OqJhs84BQWrH+Z1QOy1GDDYe+sItvQ1BhOomDT6x+ZsrMntgAItF+1kQxJ5CPRzGkYb10vr0WYukAAfcQ46fJ7Jje5ZBG8heBd61wxwKfuDDt6MD191PLWHjgy6sgA6zwXikGkQsTeeA==</SignatureValue><KeyInfo><X509Data><X509Certificate>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</X509Certificate></X509Data></KeyInfo></Signature><md:IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>MIIGbDCCBVSgAwIBAgIDA+76MA0GCSqGSIb3DQEBCwUAMIGGMQswCQYDVQQGEwJJVDEVMBMGA1UECgwMSU5GT0NFUlQgU1BBMRswGQYDVQQLDBJFbnRlIENlcnRpZmljYXRvcmUxFDASBgNVBAUTCzA3OTQ1MjExMDA2MS0wKwYDVQQDDCRJbmZvQ2VydCBTZXJ2aXppIGRpIENlcnRpZmljYXppb25lIDIwHhcNMTYwMTEyMDkyNDI4WhcNMTkwMTEyMDAwMDAwWjCBsTEUMBIGA1UELhMLMDc5NDUyMTEwMDYxDzANBgkqhkiG9w0BCQEWADEUMBIGA1UEBRMLMDc5NDUyMTEwMDYxHTAbBgNVBAMMFGlkZW50aXR5LmluZm9jZXJ0Lml0MRQwEgYDVQQLDAtJbmZvQ2VydCBJRDEhMB8GA1UECgwYSW5mb0NlcnQgU3BBLzA3OTQ1MjExMDA2MQ0wCwYDVQQHDARSb21hMQswCQYDVQQGEwJJVDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALDysrpnXB+it94LSuAmOgyFDilZ8nuSEVOFl1PX/HtgK3W25B/tqJBsyZwrAIXxg5XHYd3+i7bFoBjuduzfqhvSv9WYCVtggsz5a3sbOpU54DaOLgoCmd4nIsINwKzCmT1UNXBGjS+Xt5F3lV+v2Ayr4rAsPnkE2084BLmwcIX3w7+rx/Nd+/5HfaAMaORICYinUIvbZ5e/plUj87s1YEpep/DcC0uMFE66jFrcnHVOeHCrDh+tAZAiGew4BVJjLr0hfS4ZeaE43TJlHb00GZNfpfzGcOPbzWlSB5iF/cZbTRHmPsn0gALfpPNViniFBVqSaoywZwvkFosrehRUCNkCAwEAAaOCArQwggKwMBMGA1UdJQQMMAoGCCsGAQUFBwMCMCUGA1UdEgQeMByBGmZpcm1hLmRpZ2l0YWxlQGluZm9jZXJ0Lml0MGUGA1UdIAReMFwwWgYGK0wkAQEIMFAwTgYIKwYBBQUHAgIwQgxASW5mb0NlcnQgU3BBIFNTTCwgU01JTUUgYW5kIGRpZ2l0YWwgc2lnbmF0dXJlIENsaWVudCBDZXJ0aWZpY2F0ZTA3BggrBgEFBQcBAQQrMCkwJwYIKwYBBQUHMAGGG2h0dHA6Ly9vY3NwLnNjLmluZm9jZXJ0Lml0LzCB7AYDVR0fBIHkMIHhMDSgMqAwhi5odHRwOi8vY3JsLmluZm9jZXJ0Lml0L2NybHMvc2Vydml6aTIvQ1JMMDEuY3JsMIGooIGloIGihoGfbGRhcDovL2xkYXAuaW5mb2NlcnQuaXQvY24lM0RJbmZvQ2VydCUyMFNlcnZpemklMjBkaSUyMENlcnRpZmljYXppb25lJTIwMiUyMENSTDAxLG91JTNERW50ZSUyMENlcnRpZmljYXRvcmUsbyUzRElORk9DRVJUJTIwU1BBLEMlM0RJVD9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0MA4GA1UdDwEB/wQEAwIEsDCBswYDVR0jBIGrMIGogBTpNppkKVKhWv5ppMSDt4B9D2oSeKGBjKSBiTCBhjELMAkGA1UEBhMCSVQxFTATBgNVBAoMDElORk9DRVJUIFNQQTEbMBkGA1UECwwSRW50ZSBDZXJ0aWZpY2F0b3JlMRQwEgYDVQQFEwswNzk0NTIxMTAwNjEtMCsGA1UEAwwkSW5mb0NlcnQgU2Vydml6aSBkaSBDZXJ0aWZpY2F6aW9uZSAyggECMB0GA1UdDgQWBBTi8mIRU4ue/0lKSfv4gSQhoZQvozANBgkqhkiG9w0BAQsFAAOCAQEAUCXyjmfzxmyVQbK4cf79zj5qMZVAAjDMTR1UGFcS2IibICh3S3Uf22lPGQfm+MX9tiweETW7fBLW6lrR2ofXBz/FfU98A/AA9GZDrbGhBxoc+RoqkHVYRqEuXOq6z3X9DuvsdsfKeO3p4eXbXlCcxD2PP5fFqcZxx1WZ1HRamiGk9fMN1iT3aPa3q7TfRD6W6+XgafjXieZ8bCa1FGIfapbqsWa91jdn4xiJpbmTTq1/Zjs5RCZYzmMEV9rSuSVgFtONb8+xKC4ohMVxAUw2yZHwd4dDyBLkapuaWkzhW939+gjeoKz04Ds2C52d/kln7ehdu9LkzvRI6UAEpAYLgg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://identity.infocert.it/spid/samlslo" ResponseLocation="https://identity.infocert.it/spid/samlslo/response"/><md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://identity.infocert.it/spid/samlslo" ResponseLocation="https://identity.infocert.it/spid/samlslo/response"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://identity.infocert.it/spid/samlsso"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://identity.infocert.it/spid/samlsso"/><saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Domicilio fisico" Name="address"/><saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Ragione o denominazione sociale" Name="companyName"/><saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Provincia di nascita" Name="countyOfBirth"/><saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Data di nascita" Name="dateOfBirth"/><saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Domicilio digitale" Name="digitalAddress"/><saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Indirizzo di posta elettronica" Name="email"/><saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Data di scadenza identita" Name="expirationDate"/><saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Cognome" Name="familyName"/><saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Codice fiscale" Name="fiscalNumber"/><saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Sesso" Name="gender"/><saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Documento d''identita" Name="idCard"/><saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Partita IVA" Name="ivaCode"/><saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Numero di telefono mobile" Name="mobilePhone"/><saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Nome" Name="name"/><saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Luogo di nascita" Name="placeOfBirth"/><saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Sede legale" Name="registeredOffice"/><saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Codice identificativo SPID" Name="spidCode"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang="it">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang="en">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang="fr">InfoCert S.p.A.</md:OrganizationName><md:OrganizationName xml:lang="de">InfoCert S.p.A.</md:OrganizationName><md:OrganizationDisplayName xml:lang="it">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang="en">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang="fr">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationDisplayName xml:lang="de">InfoCert S.p.A.</md:OrganizationDisplayName><md:OrganizationURL xml:lang="it">https://www.infocert.it</md:OrganizationURL><md:OrganizationURL xml:lang="en">https://www.infocert.it/international/?lang=en</md:OrganizationURL><md:OrganizationURL xml:lang="fr">https://www.infocert.it/international/?lang=fr</md:OrganizationURL><md:OrganizationURL xml:lang="de">https://www.infocert.it/international/?lang=de</md:OrganizationURL></md:Organization></md:EntityDescriptor>', '2017-07-24 09:52:36.853002+02', NULL, true, 'infocrt');
INSERT INTO metadata ("ID", cod_metadata, xml, date, note, active, cod_provider) VALUES (5, 'poste_meta', '<?xml version="1.0" standalone="no"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ID="_5145ad9c-675b-4277-84f6-324773418d64" cacheDuration="P0Y0M30DT0H0M0.000S" entityID="https://posteid.poste.it"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#_5145ad9c-675b-4277-84f6-324773418d64"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>XiFV1ppZSffZg49dIHdB9cHMm9d7Tob66Bk4eRcX+E8=</DigestValue></Reference></SignedInfo><SignatureValue>xnJ5evn7Iv8tOciW6TGwyl/XqS59UJzGfQqGSMURyw6h5qVnHFsDz8yiqz2jI/TANHP6sCB2f0ixbfkU/8PtW7ZOVL58IMpsLvaLyuYQLImWxh2Z3giUIx8veSAI6pTMEplhQlDTYsF25bPV/TTOblYezNlJvZ31lKOMNWMS0ruNfjv+IUTLPT95Ibi3f8pZpLNh7BU5ytF48fbrIJHMLA7U0LGFPURsfeaFi4PmqGAidqOktN4HI2QxcFQUV8rBvRbibHgW2VOxEkLs6rQfkrla8NAMalauNCThCcGtZQ3vjchzOzxtZC6Ot57nadJ/qpOMboAjwSMBho5jwDgriA==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIEKzCCAxOgAwIBAgIDE2Y0MA0GCSqGSIb3DQEBCwUAMGAxCzAJBgNVBAYTAklUMRgwFgYDVQQKDA9Qb3N0ZWNvbSBTLnAuQS4xIDAeBgNVBAsMF0NlcnRpZmljYXRpb24gQXV0aG9yaXR5MRUwEwYDVQQDDAxQb3N0ZWNvbSBDQTMwHhcNMTYwMjI2MTU1MjQ0WhcNMjEwMjI2MTU1MjQ0WjBxMQswCQYDVQQGEwJJVDEOMAwGA1UECAwFSXRhbHkxDTALBgNVBAcMBFJvbWUxHjAcBgNVBAoMFVBvc3RlIEl0YWxpYW5lIFMucC5BLjENMAsGA1UECwwEU1BJRDEUMBIGA1UEAwwLSURQLVBvc3RlSUQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDZFEtJoEHFAjpCaZcj5DVWrRDyaLZyu31XApslbo87CyWz61OJMtw6QQU0MdCtrYbtSJ6vJwx7/6EUjsZ3u4x3EPLdlkyiGOqukPwATv4c7TVOUVs5onIqTphM9b+AHRg4ehiMGesm/9d7RIaLuN79iPUvdLn6WP3idAfEw+rhJ/wYEQ0h1Xm5osNUgtWcBGavZIjLssWNrDDfJYxXH3QZ0kI6feEvLCJwgjXLGkBuhFehNhM4fhbX9iUCWwwkJ3JsP2++Rc/iTA0LZhiUsXNNq7gBcLAJ9UX2V1dWjTzBHevfHspzt4e0VgIIwbDRqsRtF8VUPSDYYbLoqwbLt18XAgMBAAGjgdwwgdkwRgYDVR0gBD8wPTAwBgcrTAsBAgEBMCUwIwYIKwYBBQUHAgEWF2h0dHA6Ly93d3cucG9zdGVjZXJ0Lml0MAkGBytMCwEBCgIwDgYDVR0PAQH/BAQDAgSwMB8GA1UdIwQYMBaAFKc0XP2FByYU2l0gFzGKE8zVSzfmMD8GA1UdHwQ4MDYwNKAyoDCGLmh0dHA6Ly9wb3N0ZWNlcnQucG9zdGUuaXQvcG9zdGVjb21jYTMvY3JsMy5jcmwwHQYDVR0OBBYEFEvrikZQkfBjuiTpxExSBe8wGgsyMA0GCSqGSIb3DQEBCwUAA4IBAQBNAw8UoeiCF+1rFs27d3bEef6CLe/PJga9EfwKItjMDD9QzT/FShRWKLHlK69MHL1ZLPRPvuWUTkIOHTpNqBPILvO1u13bSg+6o+2OdqAkCBkbTqbGjWSPLaTUVNV6MbXmvttD8Vd9vIZg1xBBG3Fai13dwvSj3hAZd8ug8a8fW1y/iDbRC5D1O+HlHDuvIW4LbJ093jdj+oZwSyd216gtXL00QA0C1uMuDv9Wf9IxniTb710dRSgIcM4/eR7832fZgdOsoalFzGYWxSCs8WOZrjpub1fdaRSEuCQk2+gmdsiRcTs9EqPCCNiNlrNAiWEyGtL8A4ao3pDMwCtrb2yr</X509Certificate></X509Data></KeyInfo></Signature><md:IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>MIIEKzCCAxOgAwIBAgIDE2Y0MA0GCSqGSIb3DQEBCwUAMGAxCzAJBgNVBAYTAklUMRgwFgYDVQQKDA9Qb3N0ZWNvbSBTLnAuQS4xIDAeBgNVBAsMF0NlcnRpZmljYXRpb24gQXV0aG9yaXR5MRUwEwYDVQQDDAxQb3N0ZWNvbSBDQTMwHhcNMTYwMjI2MTU1MjQ0WhcNMjEwMjI2MTU1MjQ0WjBxMQswCQYDVQQGEwJJVDEOMAwGA1UECAwFSXRhbHkxDTALBgNVBAcMBFJvbWUxHjAcBgNVBAoMFVBvc3RlIEl0YWxpYW5lIFMucC5BLjENMAsGA1UECwwEU1BJRDEUMBIGA1UEAwwLSURQLVBvc3RlSUQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDZFEtJoEHFAjpCaZcj5DVWrRDyaLZyu31XApslbo87CyWz61OJMtw6QQU0MdCtrYbtSJ6vJwx7/6EUjsZ3u4x3EPLdlkyiGOqukPwATv4c7TVOUVs5onIqTphM9b+AHRg4ehiMGesm/9d7RIaLuN79iPUvdLn6WP3idAfEw+rhJ/wYEQ0h1Xm5osNUgtWcBGavZIjLssWNrDDfJYxXH3QZ0kI6feEvLCJwgjXLGkBuhFehNhM4fhbX9iUCWwwkJ3JsP2++Rc/iTA0LZhiUsXNNq7gBcLAJ9UX2V1dWjTzBHevfHspzt4e0VgIIwbDRqsRtF8VUPSDYYbLoqwbLt18XAgMBAAGjgdwwgdkwRgYDVR0gBD8wPTAwBgcrTAsBAgEBMCUwIwYIKwYBBQUHAgEWF2h0dHA6Ly93d3cucG9zdGVjZXJ0Lml0MAkGBytMCwEBCgIwDgYDVR0PAQH/BAQDAgSwMB8GA1UdIwQYMBaAFKc0XP2FByYU2l0gFzGKE8zVSzfmMD8GA1UdHwQ4MDYwNKAyoDCGLmh0dHA6Ly9wb3N0ZWNlcnQucG9zdGUuaXQvcG9zdGVjb21jYTMvY3JsMy5jcmwwHQYDVR0OBBYEFEvrikZQkfBjuiTpxExSBe8wGgsyMA0GCSqGSIb3DQEBCwUAA4IBAQBNAw8UoeiCF+1rFs27d3bEef6CLe/PJga9EfwKItjMDD9QzT/FShRWKLHlK69MHL1ZLPRPvuWUTkIOHTpNqBPILvO1u13bSg+6o+2OdqAkCBkbTqbGjWSPLaTUVNV6MbXmvttD8Vd9vIZg1xBBG3Fai13dwvSj3hAZd8ug8a8fW1y/iDbRC5D1O+HlHDuvIW4LbJ093jdj+oZwSyd216gtXL00QA0C1uMuDv9Wf9IxniTb710dRSgIcM4/eR7832fZgdOsoalFzGYWxSCs8WOZrjpub1fdaRSEuCQk2+gmdsiRcTs9EqPCCNiNlrNAiWEyGtL8A4ao3pDMwCtrb2yr</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://posteid.poste.it/jod-fs/sloservicepost" ResponseLocation="https://posteid.poste.it/jod-fs/sloserviceresponsepost"/><md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://posteid.poste.it/jod-fs/sloserviceredirect" ResponseLocation="https://posteid.poste.it/jod-fs/sloserviceresponseredirect"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://posteid.poste.it/jod-fs/ssoservicepost"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://posteid.poste.it/jod-fs/ssoserviceredirect"/><saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Name="familyName" NameFormat="xsi:string"/><saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Name="name" NameFormat="xsi:string"/><saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Name="spidCode" NameFormat="xsi:string"/><saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Name="fiscalNumber" NameFormat="xsi:string"/><saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Name="gender" NameFormat="xsi:string"/><saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Name="dateOfBirth" NameFormat="xsi:string"/><saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Name="placeOfBirth" NameFormat="xsi:string"/><saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Name="countyOfBirth" NameFormat="xsi:string"/><saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Name="idCard" NameFormat="xsi:string"/><saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Name="address" NameFormat="xsi:string"/><saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Name="digitalAddress" NameFormat="xsi:string"/><saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Name="expirationDate" NameFormat="xsi:string"/><saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Name="email" NameFormat="xsi:string"/><saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Name="mobilePhone" NameFormat="xsi:string"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang="it">Poste Italiane SpA</md:OrganizationName><md:OrganizationDisplayName xml:lang="it">Poste Italiane SpA</md:OrganizationDisplayName><md:OrganizationURL xml:lang="it">https://www.poste.it</md:OrganizationURL></md:Organization></md:EntityDescriptor>', '2017-07-24 09:52:50.426536+02', NULL, true, 'pt');
INSERT INTO metadata ("ID", cod_metadata, xml, date, note, active, cod_provider) VALUES (6, 'aruba_meta', '<md:EntityDescriptor ID="_525e5dd1-87bb-496d-a86f-5bb4ff3c87b6" entityID="https://loginspid.aruba.it" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#_525e5dd1-87bb-496d-a86f-5bb4ff3c87b6"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>5NrN0EoiQrdALeYEc4RjMbhw2KO2d5m0fm3FDgU/2TQ=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>Qsff9OKnzVKLfAvMQ1Dgx6szYbzz7R1qbbgmdByqb0/C7h2cgCb0DsMR4Rna1ljT5N3dQpZVzCoJqzXSQhACBp68q0m9fXPll7izkC7xcZJYt3vOnBtRdMSsUHNSTmsSNtTpD83cKLbKZ4U5SbCYzHs26/tN9MtvihbYHaW7XLpx964DsXdSNwmkOKR9hjxgrXIMvas8yJovQHeoVwu/atFgCjfqzDu1dqsowHViLeefGh6j1LBQPBU5s1TTRgB/Ml1OQQXnES0lhHRAP3ez5KdsWz1EmAEsr5qw+Zi7Olc4NmCsXpdSWhuAP5FCcQB/UyCPB0QUNCj7qAjlrxi7ug==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIExTCCA62gAwIBAgIQIHtEvEhGM77HwqsuvSbi9zANBgkqhkiG9w0BAQsFADBsMQswCQYDVQQGEwJJVDEYMBYGA1UECgwPQXJ1YmFQRUMgUy5wLkEuMSEwHwYDVQQLDBhDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eUIxIDAeBgNVBAMMF0FydWJhUEVDIFMucC5BLiBORyBDQSAyMB4XDTE3MDEyMzAwMDAwMFoXDTIwMDEyMzIzNTk1OVowgaAxCzAJBgNVBAYTAklUMRYwFAYDVQQKDA1BcnViYSBQRUMgc3BhMREwDwYDVQQLDAhQcm9kb3R0bzEWMBQGA1UEAwwNcGVjLml0IHBlYy5pdDEZMBcGA1UEBRMQWFhYWFhYMDBYMDBYMDAwWDEPMA0GA1UEKgwGcGVjLml0MQ8wDQYDVQQEDAZwZWMuaXQxETAPBgNVBC4TCDE2MzQ1MzgzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqt2oHJhcp03l73p+QYpEJ+f3jYYj0W0gos0RItZx/w4vpsiKBygaqDNVWSwfo1aPdVDIX13f62O+lBki29KTt+QWv5K6SGHDUXYPntRdEQlicIBh2Z0HfrM7fDl+xeJrMp1s4dsSQAuB5TJOlFZq7xCQuukytGWBTvjfcN/os5aEsEg+RbtZHJR26SbbUcIqWb27Swgj/9jwK+tvzLnP4w8FNvEOrNfR0XwTMNDFrwbOCuWgthv5jNBsVZaoqNwiA/MxYt+gTOMj/o5PWKk8Wpm6o/7/+lWAoxh0v8x9OkbIi+YaFpIxuCcUqsrJJk63x2gHCc2nr+yclYUhsKD/AwIDAQABo4IBLDCCASgwDgYDVR0PAQH/BAQDAgeAMB0GA1UdDgQWBBTKQ3+NPGcXFk8nX994vMTVpba1EzBHBgNVHSAEQDA+MDwGCysGAQQBgegtAQEBMC0wKwYIKwYBBQUHAgEWH2h0dHBzOi8vY2EuYXJ1YmFwZWMuaXQvY3BzLmh0bWwwWAYDVR0fBFEwTzBNoEugSYZHaHR0cDovL2NybC5hcnViYXBlYy5pdC9BcnViYVBFQ1NwQUNlcnRpZmljYXRpb25BdXRob3JpdHlCL0xhdGVzdENSTC5jcmwwHwYDVR0jBBgwFoAU8v9jQBwRQv3M3/FZ9m7omYcxR3kwMwYIKwYBBQUHAQEEJzAlMCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5hcnViYXBlYy5pdDANBgkqhkiG9w0BAQsFAAOCAQEAnEw0NuaspbpDjA5wggwFtfQydU6b3Bw2/KXPRKS2JoqGmx0SYKj+L17A2KUBa2c7gDtKXYz0FLT60Bv0pmBN/oYCgVMEBJKqwRwdki9YjEBwyCZwNEx1kDAyyqFEVU9vw/OQfrAdp7MTbuZGFKknVt7b9wOYy/Op9FiUaTg6SuOy0ep+rqhihltYNAAl4L6fY45mHvqa5vvVG30OvLW/S4uvRYUXYwY6KhWvNdDf5CnFugnuEZtHJrVe4wx9aO5GvFLFZ/mQ35C5mXPQ7nIb0CDdLBJdz82nUoLSA5BUbeXAUkfahW/hLxLdhks68/TK694xVIuiB40pvMmJwxIyDA==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><md:IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>MIIExTCCA62gAwIBAgIQIHtEvEhGM77HwqsuvSbi9zANBgkqhkiG9w0BAQsFADBsMQswCQYDVQQGEwJJVDEYMBYGA1UECgwPQXJ1YmFQRUMgUy5wLkEuMSEwHwYDVQQLDBhDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eUIxIDAeBgNVBAMMF0FydWJhUEVDIFMucC5BLiBORyBDQSAyMB4XDTE3MDEyMzAwMDAwMFoXDTIwMDEyMzIzNTk1OVowgaAxCzAJBgNVBAYTAklUMRYwFAYDVQQKDA1BcnViYSBQRUMgc3BhMREwDwYDVQQLDAhQcm9kb3R0bzEWMBQGA1UEAwwNcGVjLml0IHBlYy5pdDEZMBcGA1UEBRMQWFhYWFhYMDBYMDBYMDAwWDEPMA0GA1UEKgwGcGVjLml0MQ8wDQYDVQQEDAZwZWMuaXQxETAPBgNVBC4TCDE2MzQ1MzgzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqt2oHJhcp03l73p+QYpEJ+f3jYYj0W0gos0RItZx/w4vpsiKBygaqDNVWSwfo1aPdVDIX13f62O+lBki29KTt+QWv5K6SGHDUXYPntRdEQlicIBh2Z0HfrM7fDl+xeJrMp1s4dsSQAuB5TJOlFZq7xCQuukytGWBTvjfcN/os5aEsEg+RbtZHJR26SbbUcIqWb27Swgj/9jwK+tvzLnP4w8FNvEOrNfR0XwTMNDFrwbOCuWgthv5jNBsVZaoqNwiA/MxYt+gTOMj/o5PWKk8Wpm6o/7/+lWAoxh0v8x9OkbIi+YaFpIxuCcUqsrJJk63x2gHCc2nr+yclYUhsKD/AwIDAQABo4IBLDCCASgwDgYDVR0PAQH/BAQDAgeAMB0GA1UdDgQWBBTKQ3+NPGcXFk8nX994vMTVpba1EzBHBgNVHSAEQDA+MDwGCysGAQQBgegtAQEBMC0wKwYIKwYBBQUHAgEWH2h0dHBzOi8vY2EuYXJ1YmFwZWMuaXQvY3BzLmh0bWwwWAYDVR0fBFEwTzBNoEugSYZHaHR0cDovL2NybC5hcnViYXBlYy5pdC9BcnViYVBFQ1NwQUNlcnRpZmljYXRpb25BdXRob3JpdHlCL0xhdGVzdENSTC5jcmwwHwYDVR0jBBgwFoAU8v9jQBwRQv3M3/FZ9m7omYcxR3kwMwYIKwYBBQUHAQEEJzAlMCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5hcnViYXBlYy5pdDANBgkqhkiG9w0BAQsFAAOCAQEAnEw0NuaspbpDjA5wggwFtfQydU6b3Bw2/KXPRKS2JoqGmx0SYKj+L17A2KUBa2c7gDtKXYz0FLT60Bv0pmBN/oYCgVMEBJKqwRwdki9YjEBwyCZwNEx1kDAyyqFEVU9vw/OQfrAdp7MTbuZGFKknVt7b9wOYy/Op9FiUaTg6SuOy0ep+rqhihltYNAAl4L6fY45mHvqa5vvVG30OvLW/S4uvRYUXYwY6KhWvNdDf5CnFugnuEZtHJrVe4wx9aO5GvFLFZ/mQ35C5mXPQ7nIb0CDdLBJdz82nUoLSA5BUbeXAUkfahW/hLxLdhks68/TK694xVIuiB40pvMmJwxIyDA==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://loginspid.aruba.it/ServiceLogoutRequest"/><md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://loginspid.aruba.it/ServiceLogoutRequest"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://loginspid.aruba.it/ServiceLoginWelcome"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://loginspid.aruba.it/ServiceLoginWelcome"/><saml2:Attribute FriendlyName="Codice identificativo SPID" Name="spidCode" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"/><saml2:Attribute FriendlyName="Nome" Name="name" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"/><saml2:Attribute FriendlyName="Cognome" Name="familyName" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"/><saml2:Attribute FriendlyName="Luogo di nascita" Name="placeOfBirth" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"/><saml2:Attribute FriendlyName="Provincia di nascita" Name="countyOfBirth" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"/><saml2:Attribute FriendlyName="Data di nascita" Name="dateOfBirth" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"/><saml2:Attribute FriendlyName="Sesso" Name="gender" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"/><saml2:Attribute FriendlyName="Ragione o denominazione sociale" Name="companyName" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"/><saml2:Attribute FriendlyName="Sede legale" Name="registeredOffice" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"/><saml2:Attribute FriendlyName="Codice fiscale" Name="fiscalNumber" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"/><saml2:Attribute FriendlyName="Partita IVA" Name="ivaCode" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"/><saml2:Attribute FriendlyName="Documento d''identità" Name="idCard" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"/><saml2:Attribute FriendlyName="Numero di telefono mobile" Name="mobilePhone" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"/><saml2:Attribute FriendlyName="Indirizzo di posta elettronica" Name="email" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"/><saml2:Attribute FriendlyName="Domicilio fisico" Name="address" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"/><saml2:Attribute FriendlyName="Data di scadenza identità" Name="expirationDate" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"/><saml2:Attribute FriendlyName="Domicilio digitale" Name="digitalAddress" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang="it">ArubaPEC S.p.A.</md:OrganizationName><md:OrganizationDisplayName xml:lang="it">ArubaPEC S.p.A.</md:OrganizationDisplayName><md:OrganizationURL xml:lang="it">https://www.pec.it/</md:OrganizationURL></md:Organization></md:EntityDescriptor>', '2017-07-24 09:53:08.977349+02', NULL, true, 'aruba');
INSERT INTO metadata ("ID", cod_metadata, xml, date, note, active, cod_provider) VALUES (8, 'sielte_meta', '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" entityID="https://identity.sieltecloud.it" ID="pfxf9223e2d-feaf-64df-5f85-0836c6ae13bb"><ds:Signature>  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>  <ds:Reference URI="#pfxf9223e2d-feaf-64df-5f85-0836c6ae13bb"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>RhsAXlUGQQjl9DbpeNUMvTrmVOv7rOhD179iyISRywM=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>wARTzsPTa9bh0p7pS523hkaqPvZ60kg2emtKWJZ61LUfYosOM1SZF9J0lDL9Oi8XWFyPBBCzbnQQiUC/7j1ju8Yj0rWvV9xCzrtsxyQFU+IhkiUgm2XuyG4IRZVFVgUTvyOXMf9lopBMeuAddgWIDpqZ6UidU/9pER/pHSM75FRuA+D1tIfOBvUuQ72NvfQ2Zy5VcRr57OdiTdr5sNMnPRUhVs5KRQMsLW6UumP9ciNsfjdw7cZTnKq5noyl/wsl06RXC31KnTtiM26MPAKFk+qVRPRrluJt+wxjBqy5Mbgbmve5ZKeZbb6HHctBSVHZYNlftVJxJi/EQ7lIYogPfg==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAuthnRequestsSigned="true">    <md:KeyDescriptor use="signing">      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">        <ds:X509Data>          <ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate>        </ds:X509Data>      </ds:KeyInfo>    </md:KeyDescriptor>    <md:KeyDescriptor use="encryption">      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">        <ds:X509Data>          <ds:X509Certificate>MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=</ds:X509Certificate>        </ds:X509Data>      </ds:KeyInfo>    </md:KeyDescriptor>    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://identity.sieltecloud.it/simplesaml/saml2/idp/SLS.php"/>    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://identity.sieltecloud.it/simplesaml/saml2/idp/SLS.php"/>    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php"/>    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php"/>    <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="familyName"/>    <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="name"/>    <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="spidCode"/>    <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="fiscalNumber"/>    <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="gender"/>    <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="dateOfBirth"/>    <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="placeOfBirth"/>    <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="companyName"/>    <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="registeredOffice"/>    <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="ivaCode"/>    <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="idCard"/>    <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="mobilePhone"/>    <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="email"/>    <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="address"/>    <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="digitalAddress"/>  </md:IDPSSODescriptor>  <md:Organization>    <md:OrganizationName xml:lang="en">Sielte S.p.A.</md:OrganizationName>    <md:OrganizationName xml:lang="it">Sielte S.p.A.</md:OrganizationName>    <md:OrganizationDisplayName xml:lang="en">http://www.sielte.it</md:OrganizationDisplayName>    <md:OrganizationDisplayName xml:lang="it">http://www.sielte.it</md:OrganizationDisplayName>    <md:OrganizationURL xml:lang="en">http://www.sielte.it</md:OrganizationURL>    <md:OrganizationURL xml:lang="it">http://www.sielte.it</md:OrganizationURL>  </md:Organization></md:EntityDescriptor>', '2017-07-24 09:53:32.343043+02', NULL, true, 'sielte');


--
-- TOC entry 2870 (class 0 OID 0)
-- Dependencies: 213
-- Name: metadata_ID_seq; Type: SEQUENCE SET; Schema: saml; Owner: easyspid
--

SELECT pg_catalog.setval('"metadata_ID_seq"', 8, true);


--
-- TOC entry 2806 (class 0 OID 33836)
-- Dependencies: 204
-- Data for Name: providers; Type: TABLE DATA; Schema: saml; Owner: easyspid
--

INSERT INTO providers ("ID", cod_provider, type, description, active, date, name) VALUES (6, 'sielte', 'idp', NULL, true, '2017-06-05 15:03:08.052013+02', 'Sielte S.p.A.');
INSERT INTO providers ("ID", cod_provider, type, description, active, date, name) VALUES (7, 'titrusttech', 'idp', NULL, true, '2017-06-05 15:03:10.651666+02', 'TI Trust Technologies S.r.l.');
INSERT INTO providers ("ID", cod_provider, type, description, active, date, name) VALUES (3, 'aruba', 'idp', NULL, true, '2017-06-14 15:03:54.123923+02', 'Aruba Pec S.p.A.');
INSERT INTO providers ("ID", cod_provider, type, description, active, date, name) VALUES (8, 'sapienza', 'sp', NULL, true, '2017-06-14 15:03:54.123923+02', 'Sapienza Università di Roma');
INSERT INTO providers ("ID", cod_provider, type, description, active, date, name) VALUES (2, 'pt', 'idp', NULL, true, '2017-06-14 15:03:54.123923+02', 'Poste Italiane S.p.A.');
INSERT INTO providers ("ID", cod_provider, type, description, active, date, name) VALUES (4, 'infocrt', 'idp', NULL, true, '2017-06-14 15:03:54.123923+02', 'Infocert S.p.A.');


--
-- TOC entry 2871 (class 0 OID 0)
-- Dependencies: 203
-- Name: providers_ID_seq; Type: SEQUENCE SET; Schema: saml; Owner: easyspid
--

SELECT pg_catalog.setval('"providers_ID_seq"', 9, true);


--
-- TOC entry 2814 (class 0 OID 33992)
-- Dependencies: 212
-- Data for Name: services; Type: TABLE DATA; Schema: saml; Owner: easyspid
--

INSERT INTO services ("ID", cod_service, name, description, cod_provider, active, url) VALUES (3, 'uniroma1_srelay1', 'Infostud login', NULL, 'sapienza', true, 'https://www.studenti.uniroma1.it/spid');


--
-- TOC entry 2872 (class 0 OID 0)
-- Dependencies: 211
-- Name: services_ID_seq; Type: SEQUENCE SET; Schema: saml; Owner: easyspid
--

SELECT pg_catalog.setval('"services_ID_seq"', 3, true);


--
-- TOC entry 2818 (class 0 OID 42085)
-- Dependencies: 216
-- Data for Name: settings; Type: TABLE DATA; Schema: saml; Owner: easyspid
--

INSERT INTO settings ("ID", cod_setting, active, cod_provider, settings, advanced_settings, date, note) VALUES (1, 'sap_setting', true, 'sapienza', '{"sp": {"lang": "it", "entityId": "http://www.uniroma1.it", "NameIDFormat": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", "singleLogoutService": {"url": "http://www.uniroma1.it/spid/ssosignout", "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"}, "assertionConsumerService": {"url": "http://www.uniroma1.it/spid/consume", "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"}, "attributeConsumingService": {"serviceName": "Infostud", "serviceDescription": "Infostud Login", "requestedAttributes": [{"name": "fiscalNumber", "isRequired": true, "nameFormat": ";dklf;s", "friendlyName": "fefwe", "attributeValue": ["1", "2"]}]}, "otherAssertionConsumerService": [{"assertionConsumerService": {"url": "http://www.uniroma1.it/spid/consume", "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", "attributeConsumingService": {"serviceName": "Infostud", "serviceDescription": "Infostud Login", "requestedAttributes": [{"name": "fiscalNumber", "isRequired": true, "nameFormat": "rewre", "friendlyName": "erew", "attributeValue": ["3", "4"]}, {"name": "Nome", "isRequired": false, "nameFormat": "....", "friendlyName": "Nome del cristiano", "attributeValue": ["3", "4"]}]}}}]}, "debug": true, "strict": false}', '{"security": {"wantNameId": true, "signMetadata": true, "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256", "nameIdEncrypted": false, "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "wantMessagesSigned": true, "authnRequestsSigned": true, "logoutRequestSigned": false, "wantNameIdEncrypted": false, "logoutResponseSigned": false, "wantAssertionsSigned": true, "putMetadataValidUntil": false, "requestedAuthnContext": ["urn:oasis:names:tc:SAML:2.0:ac:classes:SpidL1"], "wantAttributeStatement": true, "wantAssertionsEncrypted": true, "putMetadataCacheDuration": false, "requestedAuthnContextComparison": "minimum"}, "organization": {"it": {"url": "http://www.uniroma1.it", "name": "Universita'' Sapienza", "displayname": "Universita'' degli Studi La Sapienza - Roma"}}, "contactPerson": {"support": {"givenName": "InfoSapienza", "emailAddress": "infostud@uniroma1.it"}, "technical": {"givenName": "InfoSapienza", "emailAddress": "infostud@uniroma1.it"}}}', '2017-06-09 17:44:19.182224+02', NULL);


--
-- TOC entry 2873 (class 0 OID 0)
-- Dependencies: 215
-- Name: settings_ID_seq; Type: SEQUENCE SET; Schema: saml; Owner: easyspid
--

SELECT pg_catalog.setval('"settings_ID_seq"', 2, true);


--
-- TOC entry 2808 (class 0 OID 33855)
-- Dependencies: 206
-- Data for Name: signatures; Type: TABLE DATA; Schema: saml; Owner: easyspid
--

INSERT INTO signatures ("ID", cod_cert, private_key, public_key, cod_provider, date, fingerprint, fingerprintalg) VALUES (8, 'cert_pt', NULL, '-----BEGIN CERTIFICATE-----
MIIEKzCCAxOgAwIBAgIDE2Y0MA0GCSqGSIb3DQEBCwUAMGAxCzAJBgNVBAYTAklUMRgwFgYDVQQK
DA9Qb3N0ZWNvbSBTLnAuQS4xIDAeBgNVBAsMF0NlcnRpZmljYXRpb24gQXV0aG9yaXR5MRUwEwYD
VQQDDAxQb3N0ZWNvbSBDQTMwHhcNMTYwMjI2MTU1MjQ0WhcNMjEwMjI2MTU1MjQ0WjBxMQswCQYD
VQQGEwJJVDEOMAwGA1UECAwFSXRhbHkxDTALBgNVBAcMBFJvbWUxHjAcBgNVBAoMFVBvc3RlIEl0
YWxpYW5lIFMucC5BLjENMAsGA1UECwwEU1BJRDEUMBIGA1UEAwwLSURQLVBvc3RlSUQwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDZFEtJoEHFAjpCaZcj5DVWrRDyaLZyu31XApslbo87
CyWz61OJMtw6QQU0MdCtrYbtSJ6vJwx7/6EUjsZ3u4x3EPLdlkyiGOqukPwATv4c7TVOUVs5onIq
TphM9b+AHRg4ehiMGesm/9d7RIaLuN79iPUvdLn6WP3idAfEw+rhJ/wYEQ0h1Xm5osNUgtWcBGav
ZIjLssWNrDDfJYxXH3QZ0kI6feEvLCJwgjXLGkBuhFehNhM4fhbX9iUCWwwkJ3JsP2++Rc/iTA0L
ZhiUsXNNq7gBcLAJ9UX2V1dWjTzBHevfHspzt4e0VgIIwbDRqsRtF8VUPSDYYbLoqwbLt18XAgMB
AAGjgdwwgdkwRgYDVR0gBD8wPTAwBgcrTAsBAgEBMCUwIwYIKwYBBQUHAgEWF2h0dHA6Ly93d3cu
cG9zdGVjZXJ0Lml0MAkGBytMCwEBCgIwDgYDVR0PAQH/BAQDAgSwMB8GA1UdIwQYMBaAFKc0XP2F
ByYU2l0gFzGKE8zVSzfmMD8GA1UdHwQ4MDYwNKAyoDCGLmh0dHA6Ly9wb3N0ZWNlcnQucG9zdGUu
aXQvcG9zdGVjb21jYTMvY3JsMy5jcmwwHQYDVR0OBBYEFEvrikZQkfBjuiTpxExSBe8wGgsyMA0G
CSqGSIb3DQEBCwUAA4IBAQBNAw8UoeiCF+1rFs27d3bEef6CLe/PJga9EfwKItjMDD9QzT/FShRW
KLHlK69MHL1ZLPRPvuWUTkIOHTpNqBPILvO1u13bSg+6o+2OdqAkCBkbTqbGjWSPLaTUVNV6MbXm
vttD8Vd9vIZg1xBBG3Fai13dwvSj3hAZd8ug8a8fW1y/iDbRC5D1O+HlHDuvIW4LbJ093jdj+oZw
Syd216gtXL00QA0C1uMuDv9Wf9IxniTb710dRSgIcM4/eR7832fZgdOsoalFzGYWxSCs8WOZrjpu
b1fdaRSEuCQk2+gmdsiRcTs9EqPCCNiNlrNAiWEyGtL8A4ao3pDMwCtrb2yr
-----END CERTIFICATE-----', 'pt', '2017-07-24 09:52:50.426536+02', 'ab1bf09a9bcaeb1e8a243bc7f98de4325c066754', 'sha1');
INSERT INTO signatures ("ID", cod_cert, private_key, public_key, cod_provider, date, fingerprint, fingerprintalg) VALUES (12, 'cert_sielte', NULL, '-----BEGIN CERTIFICATE-----
MIIDczCCAlugAwIBAgIJAMsX0iEKQM6xMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTAeFw0xNTEyMTQwODE0MTVaFw0yNTEyMTMwODE0MTVaMFAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTEgMB4GA1UEBwwXU2FuIEdyZWdvcmlvIGRpIENhdGFuaWExDzANBgNVBAoMBlNpZWx0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIRlOjM/tS9V9jYjJreqZSctuYriLfPTDgX2XdhWEbMpMpwA9p0bsbLQoC1gP0piLO+qbCsIh9+boPfb4/dLIA7E+Vmm5/+evOtzvjfHG4oXjZK6jo08QwkVV8Bm1jkakJPVZ57QFbyDSr+uBbIMY7CjA2LdgnIIwKN/kSfFhrZUMJ6ZxwegM100X5psfNPSV9WUtgHsvqlIlvydPo2rMm21sg+2d3Vtg8DthNSYRLqgazCc0NTsigrH7niSbJCO0nq/svMX2rSFdh5GFK7/pxT+c3OFWqIR8r+RX4qW+auJqkbTuNRwxV22Sm6r69ZJwV0WspvsVJi+FYqiyoWhgUCAwEAAaNQME4wHQYDVR0OBBYEFCUx063GwUhEFDllwCBe/+jdeW+XMB8GA1UdIwQYMBaAFCUx063GwUhEFDllwCBe/+jdeW+XMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADF94c3JwyBM86QBLeoUZxRYKPniba8B39FfJk0pb+LejKfZMvspOrOFgYQQ9UrS8IFkBX9Xr7/tjRbr2cPwZNjrEZhoq+NfcE09bnaWTyEl1IEKK8TWOupJj9UNVpYXX0LfIRrMwNEzAPQykOaqPOnyHxOCPTY957xXSo3jXOyvugtvPHbd+iliAzUoPm1tgiTKWS+EkQ/e22eFv5NEyT+oHiKovrQ+voPWOIvJVMjiTyxRic8fEnI9zzV0SxWvFvty77wgcYbeEuFZa3iidhojUge8o1uY/JUyQjFxcvvfAgWSIZwdHiNyWaAgwzLPmPCPsvBdR3xrlcDg/9Bd3D0=
-----END CERTIFICATE-----', 'sielte', '2017-07-24 09:53:32.343043+02', 'a8961bfc6b913b620d4fb4e36823f518f87b2ec7', 'sha1');
INSERT INTO signatures ("ID", cod_cert, private_key, public_key, cod_provider, date, fingerprint, fingerprintalg) VALUES (4, 'cert_sapienza', '-----BEGIN PRIVATE KEY-----
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G1LpGfBWyw+0qm26gnDiR6gss0ooMu0=-----END PRIVATE KEY-----', '-----BEGIN CERTIFICATE-----
MIIGljCCBH6gAwIBAgIJAO2VpEv6m6DWMA0GCSqGSIb3DQEBDQUAMIHBMQswCQYD
VQQGEwJJVDENMAsGA1UECBMEUm9tZTENMAsGA1UEBxMEUm9tZTEnMCUGA1UEChMe
VW5pdmVyc2l0eSBvZiBSb21lIExhIFNhcGllbnphMTAwLgYDVQQLEydJbmZvU2Fw
aWVuemEsIFNldHRvcmUgQ2FycmllcmUgU3R1ZGVudGkxFDASBgNVBAMTC1N0dWRl
bnRpIENBMSMwIQYJKoZIhvcNAQkBFhRpbmZvc3R1ZEB1bmlyb21hMS5pdDAeFw0x
NzA1MTgxNjA0MjNaFw0xODA1MTgxNjA0MjNaMIGmMQswCQYDVQQGEwJJVDENMAsG
A1UECBMEUm9tZTENMAsGA1UEBxMEUm9tZTEnMCUGA1UEChMeVW5pdmVyc2l0eSBv
ZiBSb21lIExhIFNhcGllbnphMREwDwYDVQQLEwhJbmZvc3R1ZDEYMBYGA1UEAxMP
d3d3LnVuaXJvbWExLml0MSMwIQYJKoZIhvcNAQkBFhRpbmZvc3R1ZEB1bmlyb21h
MS5pdDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMmP1yM0qycjfu/k
mT0TqRbiPWMCi9uYAIu5U5twhY1WEJ8lzP4UTmtg5PRfkIcf5HgIiOF5BZCFp4n5
OwcnFxXXzoJcIgMpmdcAM2ozyPPhxqQYvKOxM8jBjN6uioG6D40M5j5Qr5sneK9a
kWOYsbQ8t4LmyML3jMZKK4kfmkgb5ccE4fgHUvXmdOb+t4/jNXqIXpzbXZslexTD
91EJua8Kc3Ro4iV1+F0I/zv4BfXnAX+OOBWw3+toAnA1vF+/DCafaa/sr9yvQIho
jXVqcerYnLK/0u0dNdU9JpvD0bNXTJmXbVJakNClW0i7k929PclqC7XaRb7C2WW9
xwD4BH95gTN0pDI6f5XDf8XwTg3KI9K3Ni7m/VhYm3WMHOlFqpSXd5x/7bbD94SY
F3qo3bYqxIrynALqeQ61ASsxusktLFxUw6MyMrptwfPRLCqhWzzxyQYR2PVekS5C
QunI6GhF/7pQaPJmLYJIL9TRSTPCROodmrfumIvOdu958qmDpOOXg4bWp1OWszah
7AAqy4O5/ef0yUR+yI39wV9dxabo8TWV1HyFCpDVXyr6oNTmheL30pX2WQx1qATG
dshpFIAU4zflKMxc0tRk0c47rBmTMsocrveIk4HrQDUX8o3i0T4bwc0Y/tCrp9ze
t/hFsGPRPncOWRy44xZ18OjRLWjNAgMBAAGjgakwgaYwCQYDVR0TBAIwADAsBglg
hkgBhvhCAQ0EHxYdT3BlblNTTCBHZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0O
BBYEFBNMl6pIuv5bcO0KXUXPoCEEuIKkMB8GA1UdIwQYMBaAFB9i8gxKs7VGd5QM
lTBXkF3ffvLrMCsGA1UdEgQkMCKGIGh0dHA6Ly8xOTIuMTY4LjEwLjE4MC9zc2wv
Y2EuY3J0MA0GCSqGSIb3DQEBDQUAA4ICAQBVJC2IgPAzs/skjA0tRxPCDNuGln6c
aWf1YMaUyMRfrrmvVZRpcdPdfpL6aJfF8NSTlz1CzFOW41J2cPUBVEe38OVGJmqB
00rpBUMUB6TRdiHDhiLVlfS/EkVRZomM/KxuxZyi13vjqQBUpcdvmqqeI5QxX3rG
+29i/BzoW4aTg27d1SFLF1GG+9KuIShk05epSzZ2F+ndZHSwJ9lGYh0RQM00q2Wo
rN/kGc0BOwJTdFM/gWtumEZgixLtkBSia5M0z/JiePR7C5gaYY2db1DXMLodzQoJ
TRu0VA9ibN9SBCPg9P2peYzWyk8acdEVB+3AKBNFmoKiIaHh84U3JCh/u3lrEC06
kdX9sKmIM4WJiXIFFlvS44peUmjpb0hZWlz/GA+2EeWNYm0dBHef50R2f6PPWuRv
l1GyNne0Z7/RGQPcrI9TUEG0Dw6HQriSmTQWOaoAU8KlomDH+ChC5kbI/H4D3L2Y
MyPa5iFuNe4RCPL7071B57r0q2WsIw8sHVX8zm04msbRZV/dPwZ/0mscMfdjdQzL
npdO7ZYj0dcwaZNFLbrFKmGOmFBTj6ygj4/b6Bd4U222mtMMR4u+Lck6quWCkHcC
goQW9TCAnIbu//URPCyA+pivyvwG+vy295xIAeaQYBtWWXOIKZttmbLBcmfx4KaD
A9j3h4a3EzHoPQ==
-----END CERTIFICATE-----', 'sapienza', '2017-06-03 11:57:37.110073+02', 'bb06e869a32dbbb3a306f968d39d2730396ddf66', 'sha1');
INSERT INTO signatures ("ID", cod_cert, private_key, public_key, cod_provider, date, fingerprint, fingerprintalg) VALUES (11, 'cert_infocrt', NULL, '-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----', 'infocrt', '2017-07-24 09:52:36.853002+02', 'a0dbf5fe457e742cc606acb0e093e9ea1e965942', 'sha1');
INSERT INTO signatures ("ID", cod_cert, private_key, public_key, cod_provider, date, fingerprint, fingerprintalg) VALUES (9, 'cert_aruba', NULL, '-----BEGIN CERTIFICATE-----
MIIExTCCA62gAwIBAgIQIHtEvEhGM77HwqsuvSbi9zANBgkqhkiG9w0BAQsFADBsMQswCQYDVQQG
EwJJVDEYMBYGA1UECgwPQXJ1YmFQRUMgUy5wLkEuMSEwHwYDVQQLDBhDZXJ0aWZpY2F0aW9uIEF1
dGhvcml0eUIxIDAeBgNVBAMMF0FydWJhUEVDIFMucC5BLiBORyBDQSAyMB4XDTE3MDEyMzAwMDAw
MFoXDTIwMDEyMzIzNTk1OVowgaAxCzAJBgNVBAYTAklUMRYwFAYDVQQKDA1BcnViYSBQRUMgc3Bh
MREwDwYDVQQLDAhQcm9kb3R0bzEWMBQGA1UEAwwNcGVjLml0IHBlYy5pdDEZMBcGA1UEBRMQWFhY
WFhYMDBYMDBYMDAwWDEPMA0GA1UEKgwGcGVjLml0MQ8wDQYDVQQEDAZwZWMuaXQxETAPBgNVBC4T
CDE2MzQ1MzgzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqt2oHJhcp03l73p+QYpE
J+f3jYYj0W0gos0RItZx/w4vpsiKBygaqDNVWSwfo1aPdVDIX13f62O+lBki29KTt+QWv5K6SGHD
UXYPntRdEQlicIBh2Z0HfrM7fDl+xeJrMp1s4dsSQAuB5TJOlFZq7xCQuukytGWBTvjfcN/os5aE
sEg+RbtZHJR26SbbUcIqWb27Swgj/9jwK+tvzLnP4w8FNvEOrNfR0XwTMNDFrwbOCuWgthv5jNBs
VZaoqNwiA/MxYt+gTOMj/o5PWKk8Wpm6o/7/+lWAoxh0v8x9OkbIi+YaFpIxuCcUqsrJJk63x2gH
Cc2nr+yclYUhsKD/AwIDAQABo4IBLDCCASgwDgYDVR0PAQH/BAQDAgeAMB0GA1UdDgQWBBTKQ3+N
PGcXFk8nX994vMTVpba1EzBHBgNVHSAEQDA+MDwGCysGAQQBgegtAQEBMC0wKwYIKwYBBQUHAgEW
H2h0dHBzOi8vY2EuYXJ1YmFwZWMuaXQvY3BzLmh0bWwwWAYDVR0fBFEwTzBNoEugSYZHaHR0cDov
L2NybC5hcnViYXBlYy5pdC9BcnViYVBFQ1NwQUNlcnRpZmljYXRpb25BdXRob3JpdHlCL0xhdGVz
dENSTC5jcmwwHwYDVR0jBBgwFoAU8v9jQBwRQv3M3/FZ9m7omYcxR3kwMwYIKwYBBQUHAQEEJzAl
MCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5hcnViYXBlYy5pdDANBgkqhkiG9w0BAQsFAAOCAQEA
nEw0NuaspbpDjA5wggwFtfQydU6b3Bw2/KXPRKS2JoqGmx0SYKj+L17A2KUBa2c7gDtKXYz0FLT6
0Bv0pmBN/oYCgVMEBJKqwRwdki9YjEBwyCZwNEx1kDAyyqFEVU9vw/OQfrAdp7MTbuZGFKknVt7b
9wOYy/Op9FiUaTg6SuOy0ep+rqhihltYNAAl4L6fY45mHvqa5vvVG30OvLW/S4uvRYUXYwY6KhWv
NdDf5CnFugnuEZtHJrVe4wx9aO5GvFLFZ/mQ35C5mXPQ7nIb0CDdLBJdz82nUoLSA5BUbeXAUkfa
hW/hLxLdhks68/TK694xVIuiB40pvMmJwxIyDA==
-----END CERTIFICATE-----', 'aruba', '2017-07-24 09:53:08.977349+02', '1be9f6fbbb04d9be521e626bdaf4fb13faed5849', 'sha1');


SET search_path = jwt, pg_catalog;

--
-- TOC entry 2560 (class 2606 OID 24589)
-- Name: token token_cod_key; Type: CONSTRAINT; Schema: jwt; Owner: easyspid
--

ALTER TABLE ONLY token
    ADD CONSTRAINT token_cod_key UNIQUE (cod_token);


--
-- TOC entry 2582 (class 2606 OID 32900)
-- Name: token_payload token_payload_cod_payload_key; Type: CONSTRAINT; Schema: jwt; Owner: easyspid
--

ALTER TABLE ONLY token_payload
    ADD CONSTRAINT token_payload_cod_payload_key UNIQUE (cod_payload);


--
-- TOC entry 2584 (class 2606 OID 32898)
-- Name: token_payload token_payload_pkey; Type: CONSTRAINT; Schema: jwt; Owner: easyspid
--

ALTER TABLE ONLY token_payload
    ADD CONSTRAINT token_payload_pkey PRIMARY KEY ("ID");


--
-- TOC entry 2564 (class 2606 OID 24587)
-- Name: token token_pkey; Type: CONSTRAINT; Schema: jwt; Owner: easyspid
--

ALTER TABLE ONLY token
    ADD CONSTRAINT token_pkey PRIMARY KEY ("ID");


--
-- TOC entry 2568 (class 2606 OID 24618)
-- Name: token_schemas token_schemas_cod_schema_key; Type: CONSTRAINT; Schema: jwt; Owner: easyspid
--

ALTER TABLE ONLY token_schemas
    ADD CONSTRAINT token_schemas_cod_schema_key UNIQUE (cod_schema);


--
-- TOC entry 2570 (class 2606 OID 24616)
-- Name: token_schemas token_schemas_pkey; Type: CONSTRAINT; Schema: jwt; Owner: easyspid
--

ALTER TABLE ONLY token_schemas
    ADD CONSTRAINT token_schemas_pkey PRIMARY KEY ("ID");


--
-- TOC entry 2578 (class 2606 OID 32819)
-- Name: token_signature token_signature_cod_signature_key; Type: CONSTRAINT; Schema: jwt; Owner: easyspid
--

ALTER TABLE ONLY token_signature
    ADD CONSTRAINT token_signature_cod_signature_key UNIQUE (cod_signature);


--
-- TOC entry 2580 (class 2606 OID 32817)
-- Name: token_signature token_signature_pkey; Type: CONSTRAINT; Schema: jwt; Owner: easyspid
--

ALTER TABLE ONLY token_signature
    ADD CONSTRAINT token_signature_pkey PRIMARY KEY ("ID");


--
-- TOC entry 2574 (class 2606 OID 32799)
-- Name: token_type token_type_pk; Type: CONSTRAINT; Schema: jwt; Owner: easyspid
--

ALTER TABLE ONLY token_type
    ADD CONSTRAINT token_type_pk PRIMARY KEY ("ID");


--
-- TOC entry 2576 (class 2606 OID 32801)
-- Name: token_type token_type_un; Type: CONSTRAINT; Schema: jwt; Owner: easyspid
--

ALTER TABLE ONLY token_type
    ADD CONSTRAINT token_type_un UNIQUE (cod_type);


SET search_path = log, pg_catalog;

--
-- TOC entry 2632 (class 2606 OID 77221)
-- Name: requests request_cod_request_key; Type: CONSTRAINT; Schema: log; Owner: easyspid
--

ALTER TABLE ONLY requests
    ADD CONSTRAINT request_cod_request_key UNIQUE (cod_request);


--
-- TOC entry 2634 (class 2606 OID 77219)
-- Name: requests request_pkey; Type: CONSTRAINT; Schema: log; Owner: easyspid
--

ALTER TABLE ONLY requests
    ADD CONSTRAINT request_pkey PRIMARY KEY ("ID");


--
-- TOC entry 2636 (class 2606 OID 77270)
-- Name: responses response_cod_response_key; Type: CONSTRAINT; Schema: log; Owner: easyspid
--

ALTER TABLE ONLY responses
    ADD CONSTRAINT response_cod_response_key UNIQUE (cod_response);


--
-- TOC entry 2638 (class 2606 OID 77268)
-- Name: responses response_pkey; Type: CONSTRAINT; Schema: log; Owner: easyspid
--

ALTER TABLE ONLY responses
    ADD CONSTRAINT response_pkey PRIMARY KEY ("ID");


SET search_path = saml, pg_catalog;

--
-- TOC entry 2599 (class 2606 OID 33888)
-- Name: assertions assertions_cod_assertion_key; Type: CONSTRAINT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY assertions
    ADD CONSTRAINT assertions_cod_assertion_key UNIQUE (cod_assertion);


--
-- TOC entry 2601 (class 2606 OID 33886)
-- Name: assertions assertions_pkey; Type: CONSTRAINT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY assertions
    ADD CONSTRAINT assertions_pkey PRIMARY KEY ("ID");


--
-- TOC entry 2603 (class 2606 OID 33976)
-- Name: assertions_type assertions_type_cod_type_key; Type: CONSTRAINT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY assertions_type
    ADD CONSTRAINT assertions_type_cod_type_key UNIQUE (cod_type);


--
-- TOC entry 2605 (class 2606 OID 33974)
-- Name: assertions_type assertions_type_pkey; Type: CONSTRAINT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY assertions_type
    ADD CONSTRAINT assertions_type_pkey PRIMARY KEY ("ID");


--
-- TOC entry 2593 (class 2606 OID 33866)
-- Name: signatures certifcates_cod_cert_key; Type: CONSTRAINT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY signatures
    ADD CONSTRAINT certifcates_cod_cert_key UNIQUE (cod_cert);


--
-- TOC entry 2595 (class 2606 OID 33864)
-- Name: signatures certifcates_pkey; Type: CONSTRAINT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY signatures
    ADD CONSTRAINT certifcates_pkey PRIMARY KEY ("ID");


--
-- TOC entry 2628 (class 2606 OID 42300)
-- Name: jwt_settings jwt_settings_cod_jwt_setting_key; Type: CONSTRAINT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY jwt_settings
    ADD CONSTRAINT jwt_settings_cod_jwt_setting_key UNIQUE (cod_jwt_setting);


--
-- TOC entry 2630 (class 2606 OID 42297)
-- Name: jwt_settings jwt_settings_pkey; Type: CONSTRAINT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY jwt_settings
    ADD CONSTRAINT jwt_settings_pkey PRIMARY KEY ("ID");


--
-- TOC entry 2612 (class 2606 OID 34644)
-- Name: metadata metadata_active_cod_provider_key; Type: CONSTRAINT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY metadata
    ADD CONSTRAINT metadata_active_cod_provider_key UNIQUE (active, cod_provider);


--
-- TOC entry 2615 (class 2606 OID 34642)
-- Name: metadata metadata_cod_metadata_key; Type: CONSTRAINT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY metadata
    ADD CONSTRAINT metadata_cod_metadata_key UNIQUE (cod_metadata);


--
-- TOC entry 2618 (class 2606 OID 34640)
-- Name: metadata metadata_pkey; Type: CONSTRAINT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY metadata
    ADD CONSTRAINT metadata_pkey PRIMARY KEY ("ID");


--
-- TOC entry 2587 (class 2606 OID 33850)
-- Name: providers providers_cod_provider_key; Type: CONSTRAINT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY providers
    ADD CONSTRAINT providers_cod_provider_key UNIQUE (cod_provider);


--
-- TOC entry 2590 (class 2606 OID 33848)
-- Name: providers providers_pkey; Type: CONSTRAINT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY providers
    ADD CONSTRAINT providers_pkey PRIMARY KEY ("ID");


--
-- TOC entry 2607 (class 2606 OID 34005)
-- Name: services services_cod_service_key; Type: CONSTRAINT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY services
    ADD CONSTRAINT services_cod_service_key UNIQUE (cod_service);


--
-- TOC entry 2610 (class 2606 OID 34003)
-- Name: services services_pkey; Type: CONSTRAINT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY services
    ADD CONSTRAINT services_pkey PRIMARY KEY ("ID");


--
-- TOC entry 2620 (class 2606 OID 42099)
-- Name: settings setting_active_cod_provider_key; Type: CONSTRAINT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY settings
    ADD CONSTRAINT setting_active_cod_provider_key UNIQUE (active, cod_provider);


--
-- TOC entry 2624 (class 2606 OID 42101)
-- Name: settings setting_cod_setting_key; Type: CONSTRAINT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY settings
    ADD CONSTRAINT setting_cod_setting_key UNIQUE (cod_setting);


--
-- TOC entry 2626 (class 2606 OID 42097)
-- Name: settings setting_pkey; Type: CONSTRAINT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY settings
    ADD CONSTRAINT setting_pkey PRIMARY KEY ("ID");


SET search_path = jwt, pg_catalog;

--
-- TOC entry 2558 (class 1259 OID 32830)
-- Name: fki_token_token_type_fk; Type: INDEX; Schema: jwt; Owner: easyspid
--

CREATE INDEX fki_token_token_type_fk ON token USING btree (cod_type);


--
-- TOC entry 2561 (class 1259 OID 24591)
-- Name: token_header_idx; Type: INDEX; Schema: jwt; Owner: easyspid
--

CREATE INDEX token_header_idx ON token USING btree (header);


--
-- TOC entry 2562 (class 1259 OID 24592)
-- Name: token_payload_idx; Type: INDEX; Schema: jwt; Owner: easyspid
--

CREATE INDEX token_payload_idx ON token USING btree (payload);


--
-- TOC entry 2566 (class 1259 OID 24621)
-- Name: token_schemas_active_idx; Type: INDEX; Schema: jwt; Owner: easyspid
--

CREATE INDEX token_schemas_active_idx ON token_schemas USING btree (active);


--
-- TOC entry 2571 (class 1259 OID 24620)
-- Name: token_schemas_schema_idx; Type: INDEX; Schema: jwt; Owner: easyspid
--

CREATE INDEX token_schemas_schema_idx ON token_schemas USING btree (schema);


--
-- TOC entry 2572 (class 1259 OID 24619)
-- Name: token_schemas_type_idx; Type: INDEX; Schema: jwt; Owner: easyspid
--

CREATE INDEX token_schemas_type_idx ON token_schemas USING btree (cod_type);


--
-- TOC entry 2565 (class 1259 OID 24590)
-- Name: token_token_idx; Type: INDEX; Schema: jwt; Owner: easyspid
--

CREATE INDEX token_token_idx ON token USING btree (token);


SET search_path = saml, pg_catalog;

--
-- TOC entry 2597 (class 1259 OID 42352)
-- Name: assertions_ID_response_assertion_idx; Type: INDEX; Schema: saml; Owner: easyspid
--

CREATE INDEX "assertions_ID_response_assertion_idx" ON assertions USING btree ("ID_response_assertion");


--
-- TOC entry 2613 (class 1259 OID 34650)
-- Name: metadata_cod_metadata_idx; Type: INDEX; Schema: saml; Owner: easyspid
--

CREATE INDEX metadata_cod_metadata_idx ON metadata USING btree (cod_metadata bpchar_pattern_ops);


--
-- TOC entry 2616 (class 1259 OID 34651)
-- Name: metadata_cod_provider_idx; Type: INDEX; Schema: saml; Owner: easyspid
--

CREATE INDEX metadata_cod_provider_idx ON metadata USING btree (cod_provider);


--
-- TOC entry 2585 (class 1259 OID 33852)
-- Name: providers_active_idx; Type: INDEX; Schema: saml; Owner: easyspid
--

CREATE INDEX providers_active_idx ON providers USING btree (active);


--
-- TOC entry 2588 (class 1259 OID 33956)
-- Name: providers_name_idx; Type: INDEX; Schema: saml; Owner: easyspid
--

CREATE INDEX providers_name_idx ON providers USING btree (name);


--
-- TOC entry 2591 (class 1259 OID 33851)
-- Name: providers_type_idx; Type: INDEX; Schema: saml; Owner: easyspid
--

CREATE INDEX providers_type_idx ON providers USING btree (type);


--
-- TOC entry 2608 (class 1259 OID 34011)
-- Name: services_name_idx; Type: INDEX; Schema: saml; Owner: easyspid
--

CREATE INDEX services_name_idx ON services USING btree (name);


--
-- TOC entry 2621 (class 1259 OID 42108)
-- Name: setting_cod_provider_idx; Type: INDEX; Schema: saml; Owner: easyspid
--

CREATE INDEX setting_cod_provider_idx ON settings USING btree (cod_provider DESC);


--
-- TOC entry 2622 (class 1259 OID 42107)
-- Name: setting_cod_setting_idx; Type: INDEX; Schema: saml; Owner: easyspid
--

CREATE INDEX setting_cod_setting_idx ON settings USING btree (cod_setting DESC);


--
-- TOC entry 2596 (class 1259 OID 42043)
-- Name: signatures_fingerprint_idx; Type: INDEX; Schema: saml; Owner: easyspid
--

CREATE INDEX signatures_fingerprint_idx ON signatures USING btree (fingerprint);


SET search_path = jwt, pg_catalog;

--
-- TOC entry 2655 (class 2620 OID 32938)
-- Name: token 01_chk_token_header_insert; Type: TRIGGER; Schema: jwt; Owner: easyspid
--

CREATE TRIGGER "01_chk_token_header_insert" BEFORE INSERT ON token FOR EACH ROW EXECUTE PROCEDURE header_validator();


--
-- TOC entry 2661 (class 2620 OID 32942)
-- Name: token_signature 01_chk_token_header_insert; Type: TRIGGER; Schema: jwt; Owner: easyspid
--

CREATE TRIGGER "01_chk_token_header_insert" BEFORE INSERT ON token_signature FOR EACH ROW EXECUTE PROCEDURE header_validator();


--
-- TOC entry 2656 (class 2620 OID 32939)
-- Name: token 01_chk_token_header_update; Type: TRIGGER; Schema: jwt; Owner: easyspid
--

CREATE TRIGGER "01_chk_token_header_update" BEFORE UPDATE ON token FOR EACH ROW WHEN ((old.header IS DISTINCT FROM new.header)) EXECUTE PROCEDURE header_validator();


--
-- TOC entry 2662 (class 2620 OID 32943)
-- Name: token_signature 01_chk_token_header_update; Type: TRIGGER; Schema: jwt; Owner: easyspid
--

CREATE TRIGGER "01_chk_token_header_update" BEFORE UPDATE ON token_signature FOR EACH ROW WHEN ((old.header IS DISTINCT FROM new.header)) EXECUTE PROCEDURE header_validator();


--
-- TOC entry 2660 (class 2620 OID 33824)
-- Name: token_schemas 01_token_schemas_update; Type: TRIGGER; Schema: jwt; Owner: easyspid
--

CREATE TRIGGER "01_token_schemas_update" BEFORE UPDATE ON token_schemas FOR EACH ROW EXECUTE PROCEDURE schemas_validator();


--
-- TOC entry 2657 (class 2620 OID 32940)
-- Name: token 02_chk_token_payload_insert; Type: TRIGGER; Schema: jwt; Owner: easyspid
--

CREATE TRIGGER "02_chk_token_payload_insert" BEFORE INSERT ON token FOR EACH ROW EXECUTE PROCEDURE payload_validator();


--
-- TOC entry 2663 (class 2620 OID 32944)
-- Name: token_payload 02_chk_token_payload_insert; Type: TRIGGER; Schema: jwt; Owner: easyspid
--

CREATE TRIGGER "02_chk_token_payload_insert" BEFORE INSERT ON token_payload FOR EACH ROW EXECUTE PROCEDURE payload_validator();


--
-- TOC entry 2658 (class 2620 OID 32941)
-- Name: token 02_chk_token_payload_update; Type: TRIGGER; Schema: jwt; Owner: easyspid
--

CREATE TRIGGER "02_chk_token_payload_update" BEFORE UPDATE ON token FOR EACH ROW WHEN ((old.payload IS DISTINCT FROM new.payload)) EXECUTE PROCEDURE payload_validator();


--
-- TOC entry 2664 (class 2620 OID 32945)
-- Name: token_payload 02_chk_token_payload_update; Type: TRIGGER; Schema: jwt; Owner: easyspid
--

CREATE TRIGGER "02_chk_token_payload_update" BEFORE UPDATE ON token_payload FOR EACH ROW WHEN ((old.payload IS DISTINCT FROM new.payload)) EXECUTE PROCEDURE payload_validator();


--
-- TOC entry 2659 (class 2620 OID 77229)
-- Name: token 03_date_update; Type: TRIGGER; Schema: jwt; Owner: easyspid
--

CREATE TRIGGER "03_date_update" BEFORE UPDATE ON token FOR EACH ROW EXECUTE PROCEDURE lib.get_current_timestamp();


SET search_path = log, pg_catalog;

--
-- TOC entry 2673 (class 2620 OID 77228)
-- Name: requests 01_date_update; Type: TRIGGER; Schema: log; Owner: easyspid
--

CREATE TRIGGER "01_date_update" BEFORE UPDATE ON requests FOR EACH ROW EXECUTE PROCEDURE lib.get_current_timestamp();


--
-- TOC entry 2674 (class 2620 OID 77271)
-- Name: responses 01_date_update; Type: TRIGGER; Schema: log; Owner: easyspid
--

CREATE TRIGGER "01_date_update" BEFORE UPDATE ON responses FOR EACH ROW EXECUTE PROCEDURE lib.get_current_timestamp();


SET search_path = saml, pg_catalog;

--
-- TOC entry 2669 (class 2620 OID 77223)
-- Name: assertions 01_date_update; Type: TRIGGER; Schema: saml; Owner: easyspid
--

CREATE TRIGGER "01_date_update" BEFORE UPDATE ON assertions FOR EACH ROW EXECUTE PROCEDURE lib.get_current_timestamp();


--
-- TOC entry 2670 (class 2620 OID 77224)
-- Name: metadata 01_date_update; Type: TRIGGER; Schema: saml; Owner: easyspid
--

CREATE TRIGGER "01_date_update" BEFORE UPDATE ON metadata FOR EACH ROW EXECUTE PROCEDURE lib.get_current_timestamp();


--
-- TOC entry 2665 (class 2620 OID 77225)
-- Name: providers 01_date_update; Type: TRIGGER; Schema: saml; Owner: easyspid
--

CREATE TRIGGER "01_date_update" BEFORE UPDATE ON providers FOR EACH ROW EXECUTE PROCEDURE lib.get_current_timestamp();


--
-- TOC entry 2672 (class 2620 OID 77226)
-- Name: settings 01_date_update; Type: TRIGGER; Schema: saml; Owner: easyspid
--

CREATE TRIGGER "01_date_update" BEFORE UPDATE ON settings FOR EACH ROW EXECUTE PROCEDURE lib.get_current_timestamp();


--
-- TOC entry 2667 (class 2620 OID 77227)
-- Name: signatures 01_date_update; Type: TRIGGER; Schema: saml; Owner: easyspid
--

CREATE TRIGGER "01_date_update" BEFORE UPDATE ON signatures FOR EACH ROW EXECUTE PROCEDURE lib.get_current_timestamp();


--
-- TOC entry 2668 (class 2620 OID 42136)
-- Name: assertions 02_ID_assertion_update; Type: TRIGGER; Schema: saml; Owner: easyspid
--

CREATE TRIGGER "02_ID_assertion_update" BEFORE INSERT OR UPDATE ON assertions FOR EACH ROW EXECUTE PROCEDURE assertions();


--
-- TOC entry 2666 (class 2620 OID 42036)
-- Name: signatures 02_fingerprint_update; Type: TRIGGER; Schema: saml; Owner: easyspid
--

CREATE TRIGGER "02_fingerprint_update" BEFORE INSERT OR UPDATE ON signatures FOR EACH ROW EXECUTE PROCEDURE get_x509_fingerprint();


--
-- TOC entry 2671 (class 2620 OID 93615)
-- Name: metadata 02_put_cert; Type: TRIGGER; Schema: saml; Owner: easyspid
--

CREATE TRIGGER "02_put_cert" BEFORE INSERT OR UPDATE ON metadata FOR EACH ROW EXECUTE PROCEDURE getx509cert();


SET search_path = jwt, pg_catalog;

--
-- TOC entry 2642 (class 2606 OID 32901)
-- Name: token_payload token_payload_cod_type_fkey; Type: FK CONSTRAINT; Schema: jwt; Owner: easyspid
--

ALTER TABLE ONLY token_payload
    ADD CONSTRAINT token_payload_cod_type_fkey FOREIGN KEY (cod_type) REFERENCES token_type(cod_type) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- TOC entry 2640 (class 2606 OID 32831)
-- Name: token_schemas token_schemas_token_type_fk; Type: FK CONSTRAINT; Schema: jwt; Owner: easyspid
--

ALTER TABLE ONLY token_schemas
    ADD CONSTRAINT token_schemas_token_type_fk FOREIGN KEY (cod_type) REFERENCES token_type(cod_type) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- TOC entry 2641 (class 2606 OID 32820)
-- Name: token_signature token_signature_cod_type_fkey; Type: FK CONSTRAINT; Schema: jwt; Owner: easyspid
--

ALTER TABLE ONLY token_signature
    ADD CONSTRAINT token_signature_cod_type_fkey FOREIGN KEY (cod_type) REFERENCES token_type(cod_type) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- TOC entry 2639 (class 2606 OID 32825)
-- Name: token token_token_type_fk; Type: FK CONSTRAINT; Schema: jwt; Owner: easyspid
--

ALTER TABLE ONLY token
    ADD CONSTRAINT token_token_type_fk FOREIGN KEY (cod_type) REFERENCES token_type(cod_type) ON UPDATE CASCADE ON DELETE RESTRICT;


SET search_path = saml, pg_catalog;

--
-- TOC entry 2648 (class 2606 OID 42273)
-- Name: assertions assertions_cod_idp_fkey; Type: FK CONSTRAINT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY assertions
    ADD CONSTRAINT assertions_cod_idp_fkey FOREIGN KEY (cod_idp) REFERENCES providers(cod_provider) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- TOC entry 2647 (class 2606 OID 42268)
-- Name: assertions assertions_cod_sp_fkey; Type: FK CONSTRAINT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY assertions
    ADD CONSTRAINT assertions_cod_sp_fkey FOREIGN KEY (cod_sp) REFERENCES providers(cod_provider) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- TOC entry 2644 (class 2606 OID 33889)
-- Name: assertions assertions_cod_token_fkey; Type: FK CONSTRAINT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY assertions
    ADD CONSTRAINT assertions_cod_token_fkey FOREIGN KEY (cod_token) REFERENCES jwt.token(cod_token) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- TOC entry 2645 (class 2606 OID 33977)
-- Name: assertions assertions_cod_type_fkey; Type: FK CONSTRAINT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY assertions
    ADD CONSTRAINT assertions_cod_type_fkey FOREIGN KEY (cod_type) REFERENCES assertions_type(cod_type) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- TOC entry 2646 (class 2606 OID 42263)
-- Name: assertions assertions_providers_fk; Type: FK CONSTRAINT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY assertions
    ADD CONSTRAINT assertions_providers_fk FOREIGN KEY (cod_sp) REFERENCES providers(cod_provider) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- TOC entry 2643 (class 2606 OID 33867)
-- Name: signatures certifcates_cod_provider_fkey; Type: FK CONSTRAINT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY signatures
    ADD CONSTRAINT certifcates_cod_provider_fkey FOREIGN KEY (cod_provider) REFERENCES providers(cod_provider) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- TOC entry 2653 (class 2606 OID 42306)
-- Name: jwt_settings jwt_settings_cod_provider_fkey; Type: FK CONSTRAINT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY jwt_settings
    ADD CONSTRAINT jwt_settings_cod_provider_fkey FOREIGN KEY (cod_provider) REFERENCES providers(cod_provider) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- TOC entry 2652 (class 2606 OID 42311)
-- Name: jwt_settings jwt_settings_cod_type_assertion_fkey; Type: FK CONSTRAINT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY jwt_settings
    ADD CONSTRAINT jwt_settings_cod_type_assertion_fkey FOREIGN KEY (cod_type_assertion) REFERENCES assertions_type(cod_type) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- TOC entry 2654 (class 2606 OID 42301)
-- Name: jwt_settings jwt_settings_cod_type_token_fkey; Type: FK CONSTRAINT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY jwt_settings
    ADD CONSTRAINT jwt_settings_cod_type_token_fkey FOREIGN KEY (cod_type_token) REFERENCES jwt.token_type(cod_type) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- TOC entry 2650 (class 2606 OID 34645)
-- Name: metadata metadata_cod_provider_fkey; Type: FK CONSTRAINT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY metadata
    ADD CONSTRAINT metadata_cod_provider_fkey FOREIGN KEY (cod_provider) REFERENCES providers(cod_provider) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- TOC entry 2649 (class 2606 OID 34006)
-- Name: services services_cod_provider_fkey; Type: FK CONSTRAINT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY services
    ADD CONSTRAINT services_cod_provider_fkey FOREIGN KEY (cod_provider) REFERENCES providers(cod_provider) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- TOC entry 2651 (class 2606 OID 42102)
-- Name: settings setting_cod_provider_fkey; Type: FK CONSTRAINT; Schema: saml; Owner: easyspid
--

ALTER TABLE ONLY settings
    ADD CONSTRAINT setting_cod_provider_fkey FOREIGN KEY (cod_provider) REFERENCES providers(cod_provider) ON UPDATE CASCADE ON DELETE RESTRICT;


-- Completed on 2017-07-25 15:16:34 CEST

--
-- PostgreSQL database dump complete
--

