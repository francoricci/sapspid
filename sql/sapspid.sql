--
-- PostgreSQL database dump
--

-- Dumped from database version 9.6.2
-- Dumped by pg_dump version 9.6.2

-- Started on 2017-07-14 07:14:34 CEST

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
-- Name: jwt; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA jwt;


--
-- TOC entry 10 (class 2615 OID 16412)
-- Name: lib; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA lib;


--
-- TOC entry 12 (class 2615 OID 33833)
-- Name: saml; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA saml;


SET search_path = jwt, pg_catalog;

--
-- TOC entry 242 (class 1255 OID 32770)
-- Name: header_validator(); Type: FUNCTION; Schema: jwt; Owner: -
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


--
-- TOC entry 243 (class 1255 OID 32771)
-- Name: payload_validator(); Type: FUNCTION; Schema: jwt; Owner: -
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


--
-- TOC entry 250 (class 1255 OID 33823)
-- Name: schemas_validator(); Type: FUNCTION; Schema: jwt; Owner: -
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


SET search_path = lib, pg_catalog;

--
-- TOC entry 248 (class 1255 OID 32949)
-- Name: config_token_bytype(character varying); Type: FUNCTION; Schema: lib; Owner: -
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


--
-- TOC entry 2792 (class 0 OID 0)
-- Dependencies: 248
-- Name: FUNCTION config_token_bytype(incod_type character varying); Type: COMMENT; Schema: lib; Owner: -
--

COMMENT ON FUNCTION config_token_bytype(incod_type character varying) IS 'Configure header and payload parts of a new token and insert them into token table. Returns cod_token';


--
-- TOC entry 246 (class 1255 OID 32948)
-- Name: create_token_bytype(character varying); Type: FUNCTION; Schema: lib; Owner: -
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


--
-- TOC entry 244 (class 1255 OID 32858)
-- Name: encode_token(text, text, character varying, text); Type: FUNCTION; Schema: lib; Owner: -
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


--
-- TOC entry 2793 (class 0 OID 0)
-- Dependencies: 244
-- Name: FUNCTION encode_token(payload text, secretkey text, algorithm character varying, headers text, OUT new_token text); Type: COMMENT; Schema: lib; Owner: -
--

COMMENT ON FUNCTION encode_token(payload text, secretkey text, algorithm character varying, headers text, OUT new_token text) IS 'Simple mapping of jwt.encode function';


--
-- TOC entry 245 (class 1255 OID 32933)
-- Name: encode_token_bycod(character varying); Type: FUNCTION; Schema: lib; Owner: -
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


--
-- TOC entry 241 (class 1255 OID 24594)
-- Name: jsonvalidate(jsonb, jsonb); Type: FUNCTION; Schema: lib; Owner: -
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


--
-- TOC entry 247 (class 1255 OID 32951)
-- Name: verify_token(text, text, character varying, character varying, character varying, boolean); Type: FUNCTION; Schema: lib; Owner: -
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


--
-- TOC entry 2794 (class 0 OID 0)
-- Dependencies: 247
-- Name: FUNCTION verify_token(intoken text, secretkey text, alg character varying, aud character varying, iss character varying, inverify boolean, OUT new_token jsonb); Type: COMMENT; Schema: lib; Owner: -
--

COMMENT ON FUNCTION verify_token(intoken text, secretkey text, alg character varying, aud character varying, iss character varying, inverify boolean, OUT new_token jsonb) IS 'Simple mapping of jwt.decode function';


--
-- TOC entry 249 (class 1255 OID 32959)
-- Name: verify_token_bycod(character varying, boolean); Type: FUNCTION; Schema: lib; Owner: -
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


--
-- TOC entry 252 (class 1255 OID 42032)
-- Name: x509_fingerprint(text, character varying); Type: FUNCTION; Schema: lib; Owner: -
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


SET search_path = saml, pg_catalog;

--
-- TOC entry 254 (class 1255 OID 42120)
-- Name: assertions(); Type: FUNCTION; Schema: saml; Owner: -
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


--
-- TOC entry 251 (class 1255 OID 33961)
-- Name: get_current_timestamp(); Type: FUNCTION; Schema: saml; Owner: -
--

CREATE FUNCTION get_current_timestamp() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
NEW.date = now();
RETURN NEW;
END;
$$;


--
-- TOC entry 253 (class 1255 OID 42033)
-- Name: get_x509_fingerprint(); Type: FUNCTION; Schema: saml; Owner: -
--

CREATE FUNCTION get_x509_fingerprint() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
NEW.fingerprint = lib.x509_fingerprint(NEW.public_key, NEW.fingerprintalg);
RETURN NEW;
END;
$$;


SET search_path = jwt, pg_catalog;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- TOC entry 191 (class 1259 OID 24579)
-- Name: token; Type: TABLE; Schema: jwt; Owner: -
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


--
-- TOC entry 190 (class 1259 OID 24577)
-- Name: token_ID_seq; Type: SEQUENCE; Schema: jwt; Owner: -
--

CREATE SEQUENCE "token_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- TOC entry 2795 (class 0 OID 0)
-- Dependencies: 190
-- Name: token_ID_seq; Type: SEQUENCE OWNED BY; Schema: jwt; Owner: -
--

ALTER SEQUENCE "token_ID_seq" OWNED BY token."ID";


--
-- TOC entry 199 (class 1259 OID 32887)
-- Name: token_payload; Type: TABLE; Schema: jwt; Owner: -
--

CREATE TABLE token_payload (
    "ID" integer NOT NULL,
    cod_payload character varying(50) DEFAULT public.uuid_generate_v4() NOT NULL,
    cod_type character varying(50) DEFAULT 'jwt1'::character varying NOT NULL,
    payload jsonb DEFAULT '{"aud": "Service Provider", "exp": 1, "iat": 1, "iss": "EasySPID", "nbf": 1, "sub": "saml assertion validator"}'::jsonb NOT NULL
);


--
-- TOC entry 198 (class 1259 OID 32885)
-- Name: token_payload_ID_seq; Type: SEQUENCE; Schema: jwt; Owner: -
--

CREATE SEQUENCE "token_payload_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- TOC entry 2796 (class 0 OID 0)
-- Dependencies: 198
-- Name: token_payload_ID_seq; Type: SEQUENCE OWNED BY; Schema: jwt; Owner: -
--

ALTER SEQUENCE "token_payload_ID_seq" OWNED BY token_payload."ID";


--
-- TOC entry 193 (class 1259 OID 24605)
-- Name: token_schemas; Type: TABLE; Schema: jwt; Owner: -
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


--
-- TOC entry 192 (class 1259 OID 24603)
-- Name: token_schemas_ID_seq; Type: SEQUENCE; Schema: jwt; Owner: -
--

CREATE SEQUENCE "token_schemas_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- TOC entry 2797 (class 0 OID 0)
-- Dependencies: 192
-- Name: token_schemas_ID_seq; Type: SEQUENCE OWNED BY; Schema: jwt; Owner: -
--

ALTER SEQUENCE "token_schemas_ID_seq" OWNED BY token_schemas."ID";


--
-- TOC entry 197 (class 1259 OID 32805)
-- Name: token_signature; Type: TABLE; Schema: jwt; Owner: -
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


--
-- TOC entry 196 (class 1259 OID 32803)
-- Name: token_signature_ID_seq; Type: SEQUENCE; Schema: jwt; Owner: -
--

CREATE SEQUENCE "token_signature_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- TOC entry 2798 (class 0 OID 0)
-- Dependencies: 196
-- Name: token_signature_ID_seq; Type: SEQUENCE OWNED BY; Schema: jwt; Owner: -
--

ALTER SEQUENCE "token_signature_ID_seq" OWNED BY token_signature."ID";


--
-- TOC entry 195 (class 1259 OID 32791)
-- Name: token_type; Type: TABLE; Schema: jwt; Owner: -
--

CREATE TABLE token_type (
    "ID" integer NOT NULL,
    cod_type character varying(50) DEFAULT public.uuid_generate_v4() NOT NULL,
    note text
);


--
-- TOC entry 194 (class 1259 OID 32789)
-- Name: token_type_ID_seq; Type: SEQUENCE; Schema: jwt; Owner: -
--

CREATE SEQUENCE "token_type_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- TOC entry 2799 (class 0 OID 0)
-- Dependencies: 194
-- Name: token_type_ID_seq; Type: SEQUENCE OWNED BY; Schema: jwt; Owner: -
--

ALTER SEQUENCE "token_type_ID_seq" OWNED BY token_type."ID";


--
-- TOC entry 200 (class 1259 OID 32960)
-- Name: view_token; Type: VIEW; Schema: jwt; Owner: -
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


--
-- TOC entry 201 (class 1259 OID 32964)
-- Name: view_token_type; Type: VIEW; Schema: jwt; Owner: -
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


SET search_path = saml, pg_catalog;

--
-- TOC entry 207 (class 1259 OID 33876)
-- Name: assertions; Type: TABLE; Schema: saml; Owner: -
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


--
-- TOC entry 206 (class 1259 OID 33874)
-- Name: assertions_ID_seq; Type: SEQUENCE; Schema: saml; Owner: -
--

CREATE SEQUENCE "assertions_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- TOC entry 2800 (class 0 OID 0)
-- Dependencies: 206
-- Name: assertions_ID_seq; Type: SEQUENCE OWNED BY; Schema: saml; Owner: -
--

ALTER SEQUENCE "assertions_ID_seq" OWNED BY assertions."ID";


--
-- TOC entry 209 (class 1259 OID 33968)
-- Name: assertions_type; Type: TABLE; Schema: saml; Owner: -
--

CREATE TABLE assertions_type (
    "ID" integer NOT NULL,
    cod_type character varying(50) DEFAULT public.uuid_generate_v4() NOT NULL,
    type character varying(255) NOT NULL
);


--
-- TOC entry 208 (class 1259 OID 33966)
-- Name: assertions_type_ID_seq; Type: SEQUENCE; Schema: saml; Owner: -
--

CREATE SEQUENCE "assertions_type_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- TOC entry 2801 (class 0 OID 0)
-- Dependencies: 208
-- Name: assertions_type_ID_seq; Type: SEQUENCE OWNED BY; Schema: saml; Owner: -
--

ALTER SEQUENCE "assertions_type_ID_seq" OWNED BY assertions_type."ID";


--
-- TOC entry 205 (class 1259 OID 33855)
-- Name: signatures; Type: TABLE; Schema: saml; Owner: -
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


--
-- TOC entry 2802 (class 0 OID 0)
-- Dependencies: 205
-- Name: COLUMN signatures.private_key; Type: COMMENT; Schema: saml; Owner: -
--

COMMENT ON COLUMN signatures.private_key IS 'x509 public key';


--
-- TOC entry 2803 (class 0 OID 0)
-- Dependencies: 205
-- Name: COLUMN signatures.public_key; Type: COMMENT; Schema: saml; Owner: -
--

COMMENT ON COLUMN signatures.public_key IS 'base64 encoded x509 certificate hash';


--
-- TOC entry 2804 (class 0 OID 0)
-- Dependencies: 205
-- Name: COLUMN signatures.fingerprint; Type: COMMENT; Schema: saml; Owner: -
--

COMMENT ON COLUMN signatures.fingerprint IS 'base64 encoded x509 certificate hash';


--
-- TOC entry 2805 (class 0 OID 0)
-- Dependencies: 205
-- Name: COLUMN signatures.fingerprintalg; Type: COMMENT; Schema: saml; Owner: -
--

COMMENT ON COLUMN signatures.fingerprintalg IS 'algorithm to use in fingerprint hashing';


--
-- TOC entry 204 (class 1259 OID 33853)
-- Name: certifcates_ID_seq; Type: SEQUENCE; Schema: saml; Owner: -
--

CREATE SEQUENCE "certifcates_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- TOC entry 2806 (class 0 OID 0)
-- Dependencies: 204
-- Name: certifcates_ID_seq; Type: SEQUENCE OWNED BY; Schema: saml; Owner: -
--

ALTER SEQUENCE "certifcates_ID_seq" OWNED BY signatures."ID";


--
-- TOC entry 217 (class 1259 OID 42292)
-- Name: jwt_settings; Type: TABLE; Schema: saml; Owner: -
--

CREATE TABLE jwt_settings (
    "ID" integer NOT NULL,
    cod_jwt_setting character varying(50) DEFAULT public.uuid_generate_v4() NOT NULL,
    cod_provider character varying(50) NOT NULL,
    cod_type_assertion character varying(50) NOT NULL,
    cod_type_token character varying(50)
);


--
-- TOC entry 216 (class 1259 OID 42290)
-- Name: jwt_settings_ID_seq; Type: SEQUENCE; Schema: saml; Owner: -
--

CREATE SEQUENCE "jwt_settings_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- TOC entry 2807 (class 0 OID 0)
-- Dependencies: 216
-- Name: jwt_settings_ID_seq; Type: SEQUENCE OWNED BY; Schema: saml; Owner: -
--

ALTER SEQUENCE "jwt_settings_ID_seq" OWNED BY jwt_settings."ID";


--
-- TOC entry 213 (class 1259 OID 34628)
-- Name: metadata; Type: TABLE; Schema: saml; Owner: -
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


--
-- TOC entry 2808 (class 0 OID 0)
-- Dependencies: 213
-- Name: TABLE metadata; Type: COMMENT; Schema: saml; Owner: -
--

COMMENT ON TABLE metadata IS 'Put here Identity Providers Metadata';


--
-- TOC entry 212 (class 1259 OID 34626)
-- Name: metadata_ID_seq; Type: SEQUENCE; Schema: saml; Owner: -
--

CREATE SEQUENCE "metadata_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- TOC entry 2809 (class 0 OID 0)
-- Dependencies: 212
-- Name: metadata_ID_seq; Type: SEQUENCE OWNED BY; Schema: saml; Owner: -
--

ALTER SEQUENCE "metadata_ID_seq" OWNED BY metadata."ID";


--
-- TOC entry 203 (class 1259 OID 33836)
-- Name: providers; Type: TABLE; Schema: saml; Owner: -
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


--
-- TOC entry 202 (class 1259 OID 33834)
-- Name: providers_ID_seq; Type: SEQUENCE; Schema: saml; Owner: -
--

CREATE SEQUENCE "providers_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- TOC entry 2810 (class 0 OID 0)
-- Dependencies: 202
-- Name: providers_ID_seq; Type: SEQUENCE OWNED BY; Schema: saml; Owner: -
--

ALTER SEQUENCE "providers_ID_seq" OWNED BY providers."ID";


--
-- TOC entry 211 (class 1259 OID 33992)
-- Name: services; Type: TABLE; Schema: saml; Owner: -
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


--
-- TOC entry 2811 (class 0 OID 0)
-- Dependencies: 211
-- Name: TABLE services; Type: COMMENT; Schema: saml; Owner: -
--

COMMENT ON TABLE services IS 'Services requestd by user to service provider';


--
-- TOC entry 210 (class 1259 OID 33990)
-- Name: services_ID_seq; Type: SEQUENCE; Schema: saml; Owner: -
--

CREATE SEQUENCE "services_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- TOC entry 2812 (class 0 OID 0)
-- Dependencies: 210
-- Name: services_ID_seq; Type: SEQUENCE OWNED BY; Schema: saml; Owner: -
--

ALTER SEQUENCE "services_ID_seq" OWNED BY services."ID";


--
-- TOC entry 215 (class 1259 OID 42085)
-- Name: settings; Type: TABLE; Schema: saml; Owner: -
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


--
-- TOC entry 2813 (class 0 OID 0)
-- Dependencies: 215
-- Name: TABLE settings; Type: COMMENT; Schema: saml; Owner: -
--

COMMENT ON TABLE settings IS 'Service Providers settings';


--
-- TOC entry 214 (class 1259 OID 42083)
-- Name: settings_ID_seq; Type: SEQUENCE; Schema: saml; Owner: -
--

CREATE SEQUENCE "settings_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- TOC entry 2814 (class 0 OID 0)
-- Dependencies: 214
-- Name: settings_ID_seq; Type: SEQUENCE OWNED BY; Schema: saml; Owner: -
--

ALTER SEQUENCE "settings_ID_seq" OWNED BY settings."ID";


--
-- TOC entry 218 (class 1259 OID 50643)
-- Name: view_assertions; Type: VIEW; Schema: saml; Owner: -
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


SET search_path = jwt, pg_catalog;

--
-- TOC entry 2481 (class 2604 OID 24582)
-- Name: token ID; Type: DEFAULT; Schema: jwt; Owner: -
--

ALTER TABLE ONLY token ALTER COLUMN "ID" SET DEFAULT nextval('"token_ID_seq"'::regclass);


--
-- TOC entry 2498 (class 2604 OID 32890)
-- Name: token_payload ID; Type: DEFAULT; Schema: jwt; Owner: -
--

ALTER TABLE ONLY token_payload ALTER COLUMN "ID" SET DEFAULT nextval('"token_payload_ID_seq"'::regclass);


--
-- TOC entry 2485 (class 2604 OID 24608)
-- Name: token_schemas ID; Type: DEFAULT; Schema: jwt; Owner: -
--

ALTER TABLE ONLY token_schemas ALTER COLUMN "ID" SET DEFAULT nextval('"token_schemas_ID_seq"'::regclass);


--
-- TOC entry 2492 (class 2604 OID 32808)
-- Name: token_signature ID; Type: DEFAULT; Schema: jwt; Owner: -
--

ALTER TABLE ONLY token_signature ALTER COLUMN "ID" SET DEFAULT nextval('"token_signature_ID_seq"'::regclass);


--
-- TOC entry 2490 (class 2604 OID 32794)
-- Name: token_type ID; Type: DEFAULT; Schema: jwt; Owner: -
--

ALTER TABLE ONLY token_type ALTER COLUMN "ID" SET DEFAULT nextval('"token_type_ID_seq"'::regclass);


SET search_path = saml, pg_catalog;

--
-- TOC entry 2514 (class 2604 OID 33879)
-- Name: assertions ID; Type: DEFAULT; Schema: saml; Owner: -
--

ALTER TABLE ONLY assertions ALTER COLUMN "ID" SET DEFAULT nextval('"assertions_ID_seq"'::regclass);


--
-- TOC entry 2517 (class 2604 OID 33971)
-- Name: assertions_type ID; Type: DEFAULT; Schema: saml; Owner: -
--

ALTER TABLE ONLY assertions_type ALTER COLUMN "ID" SET DEFAULT nextval('"assertions_type_ID_seq"'::regclass);


--
-- TOC entry 2533 (class 2604 OID 42295)
-- Name: jwt_settings ID; Type: DEFAULT; Schema: saml; Owner: -
--

ALTER TABLE ONLY jwt_settings ALTER COLUMN "ID" SET DEFAULT nextval('"jwt_settings_ID_seq"'::regclass);


--
-- TOC entry 2523 (class 2604 OID 34631)
-- Name: metadata ID; Type: DEFAULT; Schema: saml; Owner: -
--

ALTER TABLE ONLY metadata ALTER COLUMN "ID" SET DEFAULT nextval('"metadata_ID_seq"'::regclass);


--
-- TOC entry 2502 (class 2604 OID 33839)
-- Name: providers ID; Type: DEFAULT; Schema: saml; Owner: -
--

ALTER TABLE ONLY providers ALTER COLUMN "ID" SET DEFAULT nextval('"providers_ID_seq"'::regclass);


--
-- TOC entry 2519 (class 2604 OID 33995)
-- Name: services ID; Type: DEFAULT; Schema: saml; Owner: -
--

ALTER TABLE ONLY services ALTER COLUMN "ID" SET DEFAULT nextval('"services_ID_seq"'::regclass);


--
-- TOC entry 2528 (class 2604 OID 42088)
-- Name: settings ID; Type: DEFAULT; Schema: saml; Owner: -
--

ALTER TABLE ONLY settings ALTER COLUMN "ID" SET DEFAULT nextval('"settings_ID_seq"'::regclass);


--
-- TOC entry 2509 (class 2604 OID 33858)
-- Name: signatures ID; Type: DEFAULT; Schema: saml; Owner: -
--

ALTER TABLE ONLY signatures ALTER COLUMN "ID" SET DEFAULT nextval('"certifcates_ID_seq"'::regclass);


SET search_path = jwt, pg_catalog;

--
-- TOC entry 2763 (class 0 OID 24579)
-- Dependencies: 191
-- Data for Name: token; Type: TABLE DATA; Schema: jwt; Owner: -
--



--
-- TOC entry 2815 (class 0 OID 0)
-- Dependencies: 190
-- Name: token_ID_seq; Type: SEQUENCE SET; Schema: jwt; Owner: -
--

SELECT pg_catalog.setval('"token_ID_seq"', 6443, true);


--
-- TOC entry 2771 (class 0 OID 32887)
-- Dependencies: 199
-- Data for Name: token_payload; Type: TABLE DATA; Schema: jwt; Owner: -
--

INSERT INTO token_payload ("ID", cod_payload, cod_type, payload) VALUES (1, 'a42eb51b-1d38-4a28-b544-d730ae97f6fd', 'jwt1', '{"aud": "Service Providers using EasySPID API", "exp": 1, "iat": 1, "iss": "EasySPID gateway", "jti": "1", "nbf": 1, "sub": "Access to EasySPID API"}');
INSERT INTO token_payload ("ID", cod_payload, cod_type, payload) VALUES (5, '38a08350-becf-4816-9177-703c77a47b44', 'jwt1_es256', '{"aud": "Service Providers validating SAML assertions", "exp": 1, "iat": 1, "iss": "EasySPID gateway", "jti": "1", "nbf": 1, "sub": "Validate SAML assertions returned from EasySPID", "saml_id": "_4d38c302617b5bf98951e65b4cf304711e2166df20"}');
INSERT INTO token_payload ("ID", cod_payload, cod_type, payload) VALUES (6, '7381d502-b6c3-4198-9347-c92cdf1fc505', 'jwt2', '{"aud": "Service Providers using EasySPID API", "exp": 1, "iat": 1, "iss": "EasySPID gateway", "jti": "1", "nbf": 1, "sub": "Access to EasySPID API"}');


--
-- TOC entry 2816 (class 0 OID 0)
-- Dependencies: 198
-- Name: token_payload_ID_seq; Type: SEQUENCE SET; Schema: jwt; Owner: -
--

SELECT pg_catalog.setval('"token_payload_ID_seq"', 6, true);


--
-- TOC entry 2765 (class 0 OID 24605)
-- Dependencies: 193
-- Data for Name: token_schemas; Type: TABLE DATA; Schema: jwt; Owner: -
--

INSERT INTO token_schemas ("ID", cod_schema, schema, active, note, cod_type, part) VALUES (1, 'b12d640d-6492-4168-bc55-b80fd72f1593', '{"id": "http://jsonschema.net", "type": "object", "$schema": "http://json-schema.org/draft-04/schema#", "required": ["typ", "alg"], "properties": {"alg": {"id": "http://jsonschema.net/alg", "type": "string", "pattern": "^HS256$", "minLength": 1}, "typ": {"id": "http://jsonschema.net/typ", "type": "string", "pattern": "^JWT$", "minLength": 1}}, "additionalProperties": true}', true, 'JWT header schema', 'jwt1', 'header');
INSERT INTO token_schemas ("ID", cod_schema, schema, active, note, cod_type, part) VALUES (10, 'a697e4d3-9916-468e-9ae6-887cc8095abf', '{"id": "http://jsonschema.net", "type": "object", "$schema": "http://json-schema.org/draft-04/schema#", "required": ["typ", "alg"], "properties": {"alg": {"id": "http://jsonschema.net/alg", "type": "string", "pattern": "^ES256$", "minLength": 1}, "typ": {"id": "http://jsonschema.net/typ", "type": "string", "pattern": "^JWT$", "minLength": 1}}, "additionalProperties": true}', true, 'JWT header schema', 'jwt1_es256', 'header');
INSERT INTO token_schemas ("ID", cod_schema, schema, active, note, cod_type, part) VALUES (11, 'e9dc2991-dd74-4c25-be76-c29ec8174b1e', '{"id": "http://jsonschema.net", "type": "object", "$schema": "http://json-schema.org/draft-04/schema#", "required": ["iss", "aud", "exp", "nbf", "iat"], "properties": {"aud": {"id": "http://jsonschema.net/aud", "type": "string", "pattern": "^Service Providers validating SAML assertions$", "minLength": 1, "description": "Identifies the recipients that the JWT is intended for"}, "exp": {"id": "http://jsonschema.net/exp", "type": "integer", "minimum": 1, "description": "Identifies the expiration time on or after which the JWT MUST NOT be accepted for processing"}, "iat": {"id": "http://jsonschema.net/iat", "type": "integer", "minimum": 1, "description": "Identifies the time at which the JWT was issued"}, "iss": {"id": "http://jsonschema.net/iss", "type": "string", "pattern": "^EasySPID gateway$", "minLength": 1, "description": "Identifies the principal that issued the JWT.  The processing of this claim is generally application specific"}, "jti": {"id": "http://jsonschema.net/jti", "type": "string", "minLength": 1, "description": "Provides a unique identifier for the JWT"}, "nbf": {"id": "http://jsonschema.net/nbf", "type": "integer", "minimum": 1, "description": "Identifies the time before which the JWT MUST NOT be accepted for processing"}, "sub": {"id": "http://jsonschema.net/sub", "type": "string", "pattern": "^Validate SAML assertions returned from EasySPID$", "minLength": 1, "description": "Identifies the principal that is the subject of the JWT"}}, "additionalProperties": true}', true, 'JWT payload schema', 'jwt1_es256', 'payload');
INSERT INTO token_schemas ("ID", cod_schema, schema, active, note, cod_type, part) VALUES (3, '10253bf0-ea39-44f1-bbed-0cdd998aef8c', '{"id": "http://jsonschema.net", "type": "object", "$schema": "http://json-schema.org/draft-04/schema#", "required": ["iss", "aud", "exp", "nbf", "iat"], "properties": {"aud": {"id": "http://jsonschema.net/aud", "type": "string", "pattern": "^Service Providers using EasySPID API$", "minLength": 1, "description": "Identifies the recipients that the JWT is intended for"}, "exp": {"id": "http://jsonschema.net/exp", "type": "integer", "minimum": 1, "description": "Identifies the expiration time on or after which the JWT MUST NOT be accepted for processing"}, "iat": {"id": "http://jsonschema.net/iat", "type": "integer", "minimum": 1, "description": "Identifies the time at which the JWT was issued"}, "iss": {"id": "http://jsonschema.net/iss", "type": "string", "pattern": "^EasySPID gateway$", "minLength": 1, "description": "Identifies the principal that issued the JWT.  The processing of this claim is generally application specific"}, "jti": {"id": "http://jsonschema.net/jti", "type": "string", "minLength": 1, "description": "Provides a unique identifier for the JWT"}, "nbf": {"id": "http://jsonschema.net/nbf", "type": "integer", "minimum": 1, "description": "Identifies the time before which the JWT MUST NOT be accepted for processing"}, "sub": {"id": "http://jsonschema.net/sub", "type": "string", "pattern": "^Access to EasySPID API$", "minLength": 1, "description": "Identifies the principal that is the subject of the JWT"}}, "additionalProperties": true}', true, 'JWT payload schema', 'jwt1', 'payload');
INSERT INTO token_schemas ("ID", cod_schema, schema, active, note, cod_type, part) VALUES (16, '85ff4c17-d059-4d62-9c55-2e36d15a14de', '{"id": "http://jsonschema.net", "type": "object", "$schema": "http://json-schema.org/draft-04/schema#", "required": ["typ", "alg"], "properties": {"alg": {"id": "http://jsonschema.net/alg", "type": "string", "pattern": "^HS256$", "minLength": 1}, "typ": {"id": "http://jsonschema.net/typ", "type": "string", "pattern": "^JWT$", "minLength": 1}}, "additionalProperties": true}', true, 'JWT header schema', 'jwt2', 'header');
INSERT INTO token_schemas ("ID", cod_schema, schema, active, note, cod_type, part) VALUES (17, '12fc974b-34ad-4371-8d15-9443f7b5c0ee', '{"id": "http://jsonschema.net", "type": "object", "$schema": "http://json-schema.org/draft-04/schema#", "required": ["iss", "aud", "exp", "nbf", "iat"], "properties": {"aud": {"id": "http://jsonschema.net/aud", "type": "string", "pattern": "^Service Providers using EasySPID API$", "minLength": 1, "description": "Identifies the recipients that the JWT is intended for"}, "exp": {"id": "http://jsonschema.net/exp", "type": "integer", "minimum": 1, "description": "Identifies the expiration time on or after which the JWT MUST NOT be accepted for processing"}, "iat": {"id": "http://jsonschema.net/iat", "type": "integer", "minimum": 1, "description": "Identifies the time at which the JWT was issued"}, "iss": {"id": "http://jsonschema.net/iss", "type": "string", "pattern": "^EasySPID gateway$", "minLength": 1, "description": "Identifies the principal that issued the JWT.  The processing of this claim is generally application specific"}, "jti": {"id": "http://jsonschema.net/jti", "type": "string", "minLength": 1, "description": "Provides a unique identifier for the JWT"}, "nbf": {"id": "http://jsonschema.net/nbf", "type": "integer", "minimum": 1, "description": "Identifies the time before which the JWT MUST NOT be accepted for processing"}, "sub": {"id": "http://jsonschema.net/sub", "type": "string", "pattern": "^Access to EasySPID API$", "minLength": 1, "description": "Identifies the principal that is the subject of the JWT"}}, "additionalProperties": true}', true, 'JWT payload schema', 'jwt2', 'payload');


--
-- TOC entry 2817 (class 0 OID 0)
-- Dependencies: 192
-- Name: token_schemas_ID_seq; Type: SEQUENCE SET; Schema: jwt; Owner: -
--

SELECT pg_catalog.setval('"token_schemas_ID_seq"', 17, true);


--
-- TOC entry 2769 (class 0 OID 32805)
-- Dependencies: 197
-- Data for Name: token_signature; Type: TABLE DATA; Schema: jwt; Owner: -
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
-- TOC entry 2818 (class 0 OID 0)
-- Dependencies: 196
-- Name: token_signature_ID_seq; Type: SEQUENCE SET; Schema: jwt; Owner: -
--

SELECT pg_catalog.setval('"token_signature_ID_seq"', 18, true);


--
-- TOC entry 2767 (class 0 OID 32791)
-- Dependencies: 195
-- Data for Name: token_type; Type: TABLE DATA; Schema: jwt; Owner: -
--

INSERT INTO token_type ("ID", cod_type, note) VALUES (1, 'jwt1', 'Default jwt type');
INSERT INTO token_type ("ID", cod_type, note) VALUES (4, 'jwt1_es256', 'jwt ECDSA 256 asymmetric keys');
INSERT INTO token_type ("ID", cod_type, note) VALUES (6, 'jwt2', 'Generic saml assertions token');


--
-- TOC entry 2819 (class 0 OID 0)
-- Dependencies: 194
-- Name: token_type_ID_seq; Type: SEQUENCE SET; Schema: jwt; Owner: -
--

SELECT pg_catalog.setval('"token_type_ID_seq"', 6, true);


SET search_path = saml, pg_catalog;

--
-- TOC entry 2777 (class 0 OID 33876)
-- Dependencies: 207
-- Data for Name: assertions; Type: TABLE DATA; Schema: saml; Owner: -
--



--
-- TOC entry 2820 (class 0 OID 0)
-- Dependencies: 206
-- Name: assertions_ID_seq; Type: SEQUENCE SET; Schema: saml; Owner: -
--

SELECT pg_catalog.setval('"assertions_ID_seq"', 3202, true);


--
-- TOC entry 2779 (class 0 OID 33968)
-- Dependencies: 209
-- Data for Name: assertions_type; Type: TABLE DATA; Schema: saml; Owner: -
--

INSERT INTO assertions_type ("ID", cod_type, type) VALUES (2, 'AuthnRequest', 'Saml Request');
INSERT INTO assertions_type ("ID", cod_type, type) VALUES (4, 'EntityDescriptor', 'Saml Metadata');
INSERT INTO assertions_type ("ID", cod_type, type) VALUES (1, 'Response', 'Saml Response');


--
-- TOC entry 2821 (class 0 OID 0)
-- Dependencies: 208
-- Name: assertions_type_ID_seq; Type: SEQUENCE SET; Schema: saml; Owner: -
--

SELECT pg_catalog.setval('"assertions_type_ID_seq"', 4, true);


--
-- TOC entry 2822 (class 0 OID 0)
-- Dependencies: 204
-- Name: certifcates_ID_seq; Type: SEQUENCE SET; Schema: saml; Owner: -
--

SELECT pg_catalog.setval('"certifcates_ID_seq"', 11, true);


--
-- TOC entry 2787 (class 0 OID 42292)
-- Dependencies: 217
-- Data for Name: jwt_settings; Type: TABLE DATA; Schema: saml; Owner: -
--

INSERT INTO jwt_settings ("ID", cod_jwt_setting, cod_provider, cod_type_assertion, cod_type_token) VALUES (2, '5d6f4883-2c26-4489-a82c-42b0567624b8', 'sapienza', 'AuthnRequest', 'jwt1');
INSERT INTO jwt_settings ("ID", cod_jwt_setting, cod_provider, cod_type_assertion, cod_type_token) VALUES (5, '8cb70e43-06b7-4461-b14c-9a116bf3f7b1', 'sapienza', 'EntityDescriptor', 'jwt1');
INSERT INTO jwt_settings ("ID", cod_jwt_setting, cod_provider, cod_type_assertion, cod_type_token) VALUES (6, '76e7d3df-35b9-434d-97ff-97003bef32c7', 'sapienza', 'Response', 'jwt1');


--
-- TOC entry 2823 (class 0 OID 0)
-- Dependencies: 216
-- Name: jwt_settings_ID_seq; Type: SEQUENCE SET; Schema: saml; Owner: -
--

SELECT pg_catalog.setval('"jwt_settings_ID_seq"', 6, true);


--
-- TOC entry 2783 (class 0 OID 34628)
-- Dependencies: 213
-- Data for Name: metadata; Type: TABLE DATA; Schema: saml; Owner: -
--

INSERT INTO metadata ("ID", cod_metadata, xml, date, note, active, cod_provider) VALUES (3, 'infocert_meta', '<?xml version="1.0" standalone="no"?><md:EntityDescriptor	xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ID="_25b183c4c721960977003fb04ec600b4" cacheDuration="P0Y0M30DT0H0M0.000S" entityID="https://identity.infocert.it">	<Signature		xmlns="http://www.w3.org/2000/09/xmldsig#">		<SignedInfo>			<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>			<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>			<Reference URI="#_25b183c4c721960977003fb04ec600b4">				<Transforms>					<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>					<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>				</Transforms>				<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>				<DigestValue>hKbiiLWanDYNT69FQLh4uWlI6rVdAfoNXltq8WE83No=</DigestValue>			</Reference>		</SignedInfo>		<SignatureValue>nqWCyBqw40iHn3OEF9qVnJIzX9xmTzoq3EE9pbpPtrrAnjBWKTI2GxCAH84oD7BArJ/oBWOEQ0iJzFLwdtJK56ly8MwFAiYdCuNm9wHd03gSGBMxaWbhQSfwkwRCmMbzxcXJGMhh4JECOdZ87KR861A+S2EPyWBHC9yx8iRZ4UtmrGpf3UWyFJsCEjCLZv+a/ld6WnkP43OqJhs84BQWrH+Z1QOy1GDDYe+sItvQ1BhOomDT6x+ZsrMntgAItF+1kQxJ5CPRzGkYb10vr0WYukAAfcQ46fJ7Jje5ZBG8heBd61wxwKfuDDt6MD191PLWHjgy6sgA6zwXikGkQsTeeA==</SignatureValue>		<KeyInfo>			<X509Data>				<X509Certificate>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</X509Certificate>			</X509Data>		</KeyInfo>	</Signature>	<md:IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">		<md:KeyDescriptor use="signing">			<ds:KeyInfo				xmlns:ds="http://www.w3.org/2000/09/xmldsig#">				<ds:X509Data>					<ds:X509Certificate>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</ds:X509Certificate>				</ds:X509Data>			</ds:KeyInfo>		</md:KeyDescriptor>		<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://identity.infocert.it/spid/samlslo" ResponseLocation="https://identity.infocert.it/spid/samlslo/response"/>		<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://identity.infocert.it/spid/samlslo" ResponseLocation="https://identity.infocert.it/spid/samlslo/response"/>		<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>		<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://identity.infocert.it/spid/samlsso"/>		<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://identity.infocert.it/spid/samlsso"/>		<saml2:Attribute			xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Domicilio fisico" Name="address"/>			<saml2:Attribute				xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Ragione o denominazione sociale" Name="companyName"/>				<saml2:Attribute					xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Provincia di nascita" Name="countyOfBirth"/>					<saml2:Attribute						xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Data di nascita" Name="dateOfBirth"/>						<saml2:Attribute							xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Domicilio digitale" Name="digitalAddress"/>							<saml2:Attribute								xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Indirizzo di posta elettronica" Name="email"/>								<saml2:Attribute									xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Data di scadenza identita" Name="expirationDate"/>									<saml2:Attribute										xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Cognome" Name="familyName"/>										<saml2:Attribute											xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Codice fiscale" Name="fiscalNumber"/>											<saml2:Attribute												xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Sesso" Name="gender"/>												<saml2:Attribute													xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Documento d''identita" Name="idCard"/>													<saml2:Attribute														xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Partita IVA" Name="ivaCode"/>														<saml2:Attribute															xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Numero di telefono mobile" Name="mobilePhone"/>															<saml2:Attribute																xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Nome" Name="name"/>																<saml2:Attribute																	xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Luogo di nascita" Name="placeOfBirth"/>																	<saml2:Attribute																		xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Sede legale" Name="registeredOffice"/>																		<saml2:Attribute																			xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" FriendlyName="Codice identificativo SPID" Name="spidCode"/>																		</md:IDPSSODescriptor>																		<md:Organization>																			<md:OrganizationName xml:lang="it">InfoCert S.p.A.</md:OrganizationName>																			<md:OrganizationName xml:lang="en">InfoCert S.p.A.</md:OrganizationName>																			<md:OrganizationName xml:lang="fr">InfoCert S.p.A.</md:OrganizationName>																			<md:OrganizationName xml:lang="de">InfoCert S.p.A.</md:OrganizationName>																			<md:OrganizationDisplayName xml:lang="it">InfoCert S.p.A.</md:OrganizationDisplayName>																			<md:OrganizationDisplayName xml:lang="en">InfoCert S.p.A.</md:OrganizationDisplayName>																			<md:OrganizationDisplayName xml:lang="fr">InfoCert S.p.A.</md:OrganizationDisplayName>																			<md:OrganizationDisplayName xml:lang="de">InfoCert S.p.A.</md:OrganizationDisplayName>																			<md:OrganizationURL xml:lang="it">https://www.infocert.it</md:OrganizationURL>																			<md:OrganizationURL xml:lang="en">https://www.infocert.it/international/?lang=en</md:OrganizationURL>																			<md:OrganizationURL xml:lang="fr">https://www.infocert.it/international/?lang=fr</md:OrganizationURL>																			<md:OrganizationURL xml:lang="de">https://www.infocert.it/international/?lang=de</md:OrganizationURL>																		</md:Organization>																	</md:EntityDescriptor>', '2017-06-03 11:45:56.892354+02', NULL, true, 'infocrt');
INSERT INTO metadata ("ID", cod_metadata, xml, date, note, active, cod_provider) VALUES (5, 'poste_meta', '<?xml version="1.0" standalone="no"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ID="_e71a0e29-5e4e-4cd8-96e8-2565b59dc10d" cacheDuration="P0Y0M30DT0H0M0.000S" entityID="https://posteid.poste.it">
	<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
		<SignedInfo>
			<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
			<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
			<Reference URI="#_e71a0e29-5e4e-4cd8-96e8-2565b59dc10d">
				<Transforms>
					<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
					<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
				</Transforms>
				<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
				<DigestValue>1JtZydtnbka/E1lmfhnbJ1orFWA=</DigestValue>
			</Reference>
		</SignedInfo>
		<SignatureValue>FuabOFmh6Ejv2yIvEPLwlCoBqLEFwVS0gHTvGDwbH/5t1kpUCxlPO2N6/aVga248J54ZiCVH4VUA
K9H6+/WJ8xwPgjhUZRpEk2Bhz2Hxpkq2u/1xw53NDCaxIvjQ5TEx75QA0NxpqZMqRB0/VgmaxkTm
IDR8h4PhHf+RJiZKS93WlPH8KW8q9nzLgTZpFHjp64JfDdbQ+YnBJ96hVQgHSVDEAkCHPxI0087s
f3LNvQB5zPVdtT4MDz00CMDpdm9QbyZfHm/AH9CIwe8LurJG4DQfJdEY0hIvP6IiP/jIf2kC/gW6
1CWc/P5DAavi4T5GD6eU3sdRs5gyoY7aryMMzA==</SignatureValue>
		<KeyInfo>
			<X509Data>
				<X509Certificate>MIIEKzCCAxOgAwIBAgIDE2Y0MA0GCSqGSIb3DQEBCwUAMGAxCzAJBgNVBAYTAklUMRgwFgYDVQQK
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
b1fdaRSEuCQk2+gmdsiRcTs9EqPCCNiNlrNAiWEyGtL8A4ao3pDMwCtrb2yr</X509Certificate>
			</X509Data>
		</KeyInfo>
	</Signature>
	<md:IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
		<md:KeyDescriptor use="signing">
			<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
				<ds:X509Data>
					<ds:X509Certificate>MIIEKzCCAxOgAwIBAgIDE2Y0MA0GCSqGSIb3DQEBCwUAMGAxCzAJBgNVBAYTAklUMRgwFgYDVQQK
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
b1fdaRSEuCQk2+gmdsiRcTs9EqPCCNiNlrNAiWEyGtL8A4ao3pDMwCtrb2yr</ds:X509Certificate>
				</ds:X509Data>
			</ds:KeyInfo>
		</md:KeyDescriptor>
		<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://posteid.poste.it/jod-fs/sloservicepost"/>
		<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
		<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://posteid.poste.it/jod-fs/ssoservicepost"/>
		<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://posteid.poste.it/jod-fs/ssoserviceredirect"/>
		<saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Name="familyName" NameFormat="xsi:string"/>
		<saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Name="name" NameFormat="xsi:string"/>
		<saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Name="spidCode" NameFormat="xsi:string"/>
		<saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Name="fiscalNumber" NameFormat="xsi:string"/>
		<saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Name="gender" NameFormat="xsi:string"/>
		<saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Name="dateOfBirth" NameFormat="xsi:string"/>
		<saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Name="placeOfBirth" NameFormat="xsi:string"/>
		<saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Name="countyOfBirth" NameFormat="xsi:string"/>
		<saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Name="idCard" NameFormat="xsi:string"/>
		<saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Name="address" NameFormat="xsi:string"/>
		<saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Name="digitalAddress" NameFormat="xsi:string"/>
		<saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Name="expirationDate" NameFormat="xsi:string"/>
		<saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Name="email" NameFormat="xsi:string"/>
		<saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Name="mobilePhone" NameFormat="xsi:string"/>
		<saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Name="fiscalNumberETSI" NameFormat="xsi:string"/>
	</md:IDPSSODescriptor>
	<md:Organization>
		<md:OrganizationName xml:lang="it">Poste Italiane SpA</md:OrganizationName>
		<md:OrganizationURL xml:lang="it">http://www.poste.it</md:OrganizationURL>
	</md:Organization>
</md:EntityDescriptor>', '2017-06-03 11:46:56.528893+02', NULL, true, 'pt');
INSERT INTO metadata ("ID", cod_metadata, xml, date, note, active, cod_provider) VALUES (6, 'aruba_meta', '<md:EntityDescriptor ID="_72fdf30b-a9ce-4c6c-b291-35ef8703eb8b" entityID="https://loginspid.aruba.it" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#_72fdf30b-a9ce-4c6c-b291-35ef8703eb8b"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>vccEDPyKTTXOtfcX4dfYKhUw2wW4+ppcCd+j/VZUHBA=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>W2I6KeoDSHB//aTO0SL+cy2d6Vb3kLqqSvmNdayxy30FYY2Eohq19RVX77XAKMs6zpyuyjG4cfrkifkBIrMvbZGZwI5a932V0COxNkWg0DXLGvMiNPUV48/WVG9RohFJGYwfIu/mDjWyRcLO2q8OtXReeH6VBYJwKNS1juw6v81b5R5vqWUfrn9fw6Pw39nJ1EGmSM39kJjyq9Y1Ltk1WgrDVukNqDI5Vltr2UHhgDW1TyLtkDT5YCTSmXD2i4OYf0s58P4YfBU8P8QclH+F0U3gfiLNvxQy0gu+rlRjo4KtZsbLt4ylb/25frQXHKkEPK7c9uSzpDgQvF5IFj5IJw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIExTCCA62gAwIBAgIQIHtEvEhGM77HwqsuvSbi9zANBgkqhkiG9w0BAQsFADBsMQswCQYDVQQGEwJJVDEYMBYGA1UECgwPQXJ1YmFQRUMgUy5wLkEuMSEwHwYDVQQLDBhDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eUIxIDAeBgNVBAMMF0FydWJhUEVDIFMucC5BLiBORyBDQSAyMB4XDTE3MDEyMzAwMDAwMFoXDTIwMDEyMzIzNTk1OVowgaAxCzAJBgNVBAYTAklUMRYwFAYDVQQKDA1BcnViYSBQRUMgc3BhMREwDwYDVQQLDAhQcm9kb3R0bzEWMBQGA1UEAwwNcGVjLml0IHBlYy5pdDEZMBcGA1UEBRMQWFhYWFhYMDBYMDBYMDAwWDEPMA0GA1UEKgwGcGVjLml0MQ8wDQYDVQQEDAZwZWMuaXQxETAPBgNVBC4TCDE2MzQ1MzgzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqt2oHJhcp03l73p+QYpEJ+f3jYYj0W0gos0RItZx/w4vpsiKBygaqDNVWSwfo1aPdVDIX13f62O+lBki29KTt+QWv5K6SGHDUXYPntRdEQlicIBh2Z0HfrM7fDl+xeJrMp1s4dsSQAuB5TJOlFZq7xCQuukytGWBTvjfcN/os5aEsEg+RbtZHJR26SbbUcIqWb27Swgj/9jwK+tvzLnP4w8FNvEOrNfR0XwTMNDFrwbOCuWgthv5jNBsVZaoqNwiA/MxYt+gTOMj/o5PWKk8Wpm6o/7/+lWAoxh0v8x9OkbIi+YaFpIxuCcUqsrJJk63x2gHCc2nr+yclYUhsKD/AwIDAQABo4IBLDCCASgwDgYDVR0PAQH/BAQDAgeAMB0GA1UdDgQWBBTKQ3+NPGcXFk8nX994vMTVpba1EzBHBgNVHSAEQDA+MDwGCysGAQQBgegtAQEBMC0wKwYIKwYBBQUHAgEWH2h0dHBzOi8vY2EuYXJ1YmFwZWMuaXQvY3BzLmh0bWwwWAYDVR0fBFEwTzBNoEugSYZHaHR0cDovL2NybC5hcnViYXBlYy5pdC9BcnViYVBFQ1NwQUNlcnRpZmljYXRpb25BdXRob3JpdHlCL0xhdGVzdENSTC5jcmwwHwYDVR0jBBgwFoAU8v9jQBwRQv3M3/FZ9m7omYcxR3kwMwYIKwYBBQUHAQEEJzAlMCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5hcnViYXBlYy5pdDANBgkqhkiG9w0BAQsFAAOCAQEAnEw0NuaspbpDjA5wggwFtfQydU6b3Bw2/KXPRKS2JoqGmx0SYKj+L17A2KUBa2c7gDtKXYz0FLT60Bv0pmBN/oYCgVMEBJKqwRwdki9YjEBwyCZwNEx1kDAyyqFEVU9vw/OQfrAdp7MTbuZGFKknVt7b9wOYy/Op9FiUaTg6SuOy0ep+rqhihltYNAAl4L6fY45mHvqa5vvVG30OvLW/S4uvRYUXYwY6KhWvNdDf5CnFugnuEZtHJrVe4wx9aO5GvFLFZ/mQ35C5mXPQ7nIb0CDdLBJdz82nUoLSA5BUbeXAUkfahW/hLxLdhks68/TK694xVIuiB40pvMmJwxIyDA==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><md:IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>MIIExTCCA62gAwIBAgIQIHtEvEhGM77HwqsuvSbi9zANBgkqhkiG9w0BAQsFADBsMQswCQYDVQQGEwJJVDEYMBYGA1UECgwPQXJ1YmFQRUMgUy5wLkEuMSEwHwYDVQQLDBhDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eUIxIDAeBgNVBAMMF0FydWJhUEVDIFMucC5BLiBORyBDQSAyMB4XDTE3MDEyMzAwMDAwMFoXDTIwMDEyMzIzNTk1OVowgaAxCzAJBgNVBAYTAklUMRYwFAYDVQQKDA1BcnViYSBQRUMgc3BhMREwDwYDVQQLDAhQcm9kb3R0bzEWMBQGA1UEAwwNcGVjLml0IHBlYy5pdDEZMBcGA1UEBRMQWFhYWFhYMDBYMDBYMDAwWDEPMA0GA1UEKgwGcGVjLml0MQ8wDQYDVQQEDAZwZWMuaXQxETAPBgNVBC4TCDE2MzQ1MzgzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqt2oHJhcp03l73p+QYpEJ+f3jYYj0W0gos0RItZx/w4vpsiKBygaqDNVWSwfo1aPdVDIX13f62O+lBki29KTt+QWv5K6SGHDUXYPntRdEQlicIBh2Z0HfrM7fDl+xeJrMp1s4dsSQAuB5TJOlFZq7xCQuukytGWBTvjfcN/os5aEsEg+RbtZHJR26SbbUcIqWb27Swgj/9jwK+tvzLnP4w8FNvEOrNfR0XwTMNDFrwbOCuWgthv5jNBsVZaoqNwiA/MxYt+gTOMj/o5PWKk8Wpm6o/7/+lWAoxh0v8x9OkbIi+YaFpIxuCcUqsrJJk63x2gHCc2nr+yclYUhsKD/AwIDAQABo4IBLDCCASgwDgYDVR0PAQH/BAQDAgeAMB0GA1UdDgQWBBTKQ3+NPGcXFk8nX994vMTVpba1EzBHBgNVHSAEQDA+MDwGCysGAQQBgegtAQEBMC0wKwYIKwYBBQUHAgEWH2h0dHBzOi8vY2EuYXJ1YmFwZWMuaXQvY3BzLmh0bWwwWAYDVR0fBFEwTzBNoEugSYZHaHR0cDovL2NybC5hcnViYXBlYy5pdC9BcnViYVBFQ1NwQUNlcnRpZmljYXRpb25BdXRob3JpdHlCL0xhdGVzdENSTC5jcmwwHwYDVR0jBBgwFoAU8v9jQBwRQv3M3/FZ9m7omYcxR3kwMwYIKwYBBQUHAQEEJzAlMCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5hcnViYXBlYy5pdDANBgkqhkiG9w0BAQsFAAOCAQEAnEw0NuaspbpDjA5wggwFtfQydU6b3Bw2/KXPRKS2JoqGmx0SYKj+L17A2KUBa2c7gDtKXYz0FLT60Bv0pmBN/oYCgVMEBJKqwRwdki9YjEBwyCZwNEx1kDAyyqFEVU9vw/OQfrAdp7MTbuZGFKknVt7b9wOYy/Op9FiUaTg6SuOy0ep+rqhihltYNAAl4L6fY45mHvqa5vvVG30OvLW/S4uvRYUXYwY6KhWvNdDf5CnFugnuEZtHJrVe4wx9aO5GvFLFZ/mQ35C5mXPQ7nIb0CDdLBJdz82nUoLSA5BUbeXAUkfahW/hLxLdhks68/TK694xVIuiB40pvMmJwxIyDA==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://loginspid.aruba.it/ServiceLogoutRequest"/><md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://loginspid.aruba.it/ServiceLogoutRequest"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://loginspid.aruba.it/ServiceLoginWelcome"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://loginspid.aruba.it/ServiceLoginWelcome"/><saml2:Attribute FriendlyName="Codice identificativo SPID" Name="spidCode" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"/><saml2:Attribute FriendlyName="Nome" Name="name" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"/><saml2:Attribute FriendlyName="Cognome" Name="familyName" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"/><saml2:Attribute FriendlyName="Luogo di nascita" Name="placeOfBirth" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"/><saml2:Attribute FriendlyName="Provincia di nascita" Name="countyOfBirth" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"/><saml2:Attribute FriendlyName="Data di nascita" Name="dateOfBirth" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"/><saml2:Attribute FriendlyName="Sesso" Name="gender" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"/><saml2:Attribute FriendlyName="Ragione o denominazione sociale" Name="companyName" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"/><saml2:Attribute FriendlyName="Sede legale" Name="registeredOffice" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"/><saml2:Attribute FriendlyName="Codice fiscale" Name="fiscalNumber" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"/><saml2:Attribute FriendlyName="Partita IVA" Name="ivaCode" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"/><saml2:Attribute FriendlyName="Documento d''identità" Name="idCard" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"/><saml2:Attribute FriendlyName="Numero di telefono mobile" Name="mobilePhone" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"/><saml2:Attribute FriendlyName="Indirizzo di posta elettronica" Name="email" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"/><saml2:Attribute FriendlyName="Domicilio fisico" Name="address" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"/><saml2:Attribute FriendlyName="Data di scadenza identità" Name="expirationDate" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"/><saml2:Attribute FriendlyName="Domicilio digitale" Name="digitalAddress" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"/></md:IDPSSODescriptor><md:Organization><md:OrganizationName xml:lang="it">ArubaPEC S.p.A.</md:OrganizationName><md:OrganizationDisplayName xml:lang="it">ArubaPEC S.p.A.</md:OrganizationDisplayName><md:OrganizationURL xml:lang="it">https://www.pec.it/</md:OrganizationURL></md:Organization></md:EntityDescriptor>', '2017-06-09 16:50:05.836118+02', NULL, true, 'aruba');


--
-- TOC entry 2824 (class 0 OID 0)
-- Dependencies: 212
-- Name: metadata_ID_seq; Type: SEQUENCE SET; Schema: saml; Owner: -
--

SELECT pg_catalog.setval('"metadata_ID_seq"', 6, true);


--
-- TOC entry 2773 (class 0 OID 33836)
-- Dependencies: 203
-- Data for Name: providers; Type: TABLE DATA; Schema: saml; Owner: -
--

INSERT INTO providers ("ID", cod_provider, type, description, active, date, name) VALUES (6, 'sielte', 'idp', NULL, true, '2017-06-05 15:03:08.052013+02', 'Sielte S.p.A.');
INSERT INTO providers ("ID", cod_provider, type, description, active, date, name) VALUES (7, 'titrusttech', 'idp', NULL, true, '2017-06-05 15:03:10.651666+02', 'TI Trust Technologies S.r.l.');
INSERT INTO providers ("ID", cod_provider, type, description, active, date, name) VALUES (3, 'aruba', 'idp', NULL, true, '2017-06-14 15:03:54.123923+02', 'Aruba Pec S.p.A.');
INSERT INTO providers ("ID", cod_provider, type, description, active, date, name) VALUES (8, 'sapienza', 'sp', NULL, true, '2017-06-14 15:03:54.123923+02', 'Sapienza Università di Roma');
INSERT INTO providers ("ID", cod_provider, type, description, active, date, name) VALUES (2, 'pt', 'idp', NULL, true, '2017-06-14 15:03:54.123923+02', 'Poste Italiane S.p.A.');
INSERT INTO providers ("ID", cod_provider, type, description, active, date, name) VALUES (4, 'infocrt', 'idp', NULL, true, '2017-06-14 15:03:54.123923+02', 'Infocert S.p.A.');


--
-- TOC entry 2825 (class 0 OID 0)
-- Dependencies: 202
-- Name: providers_ID_seq; Type: SEQUENCE SET; Schema: saml; Owner: -
--

SELECT pg_catalog.setval('"providers_ID_seq"', 9, true);


--
-- TOC entry 2781 (class 0 OID 33992)
-- Dependencies: 211
-- Data for Name: services; Type: TABLE DATA; Schema: saml; Owner: -
--

--
-- TOC entry 2826 (class 0 OID 0)
-- Dependencies: 210
-- Name: services_ID_seq; Type: SEQUENCE SET; Schema: saml; Owner: -
--

SELECT pg_catalog.setval('"services_ID_seq"', 3, true);


--
-- TOC entry 2785 (class 0 OID 42085)
-- Dependencies: 215
-- Data for Name: settings; Type: TABLE DATA; Schema: saml; Owner: -
--

INSERT INTO settings ("ID", cod_setting, active, cod_provider, settings, advanced_settings, date, note) VALUES (1, 'sap_setting', true, 'sapienza', '{"sp": {"lang": "it", "entityId": "http://www.uniroma1.it", "NameIDFormat": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", "singleLogoutService": {"url": "http://www.uniroma1.it/spid/ssosignout", "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"}, "assertionConsumerService": {"url": "http://www.uniroma1.it/spid/consume", "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"}, "attributeConsumingService": {"serviceName": "Infostud", "serviceDescription": "Infostud Login", "requestedAttributes": [{"name": "fiscalNumber", "isRequired": true, "nameFormat": ";dklf;s", "friendlyName": "fefwe", "attributeValue": ["1", "2"]}]}, "otherAssertionConsumerService": [{"assertionConsumerService": {"url": "http://www.uniroma1.it/spid/consume", "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", "attributeConsumingService": {"serviceName": "Infostud", "serviceDescription": "Infostud Login", "requestedAttributes": [{"name": "fiscalNumber", "isRequired": true, "nameFormat": "rewre", "friendlyName": "erew", "attributeValue": ["3", "4"]}, {"name": "Nome", "isRequired": false, "nameFormat": "....", "friendlyName": "Nome del cristiano", "attributeValue": ["3", "4"]}]}}}]}, "debug": true, "strict": false}', '{"security": {"wantNameId": true, "signMetadata": true, "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256", "nameIdEncrypted": false, "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "wantMessagesSigned": true, "authnRequestsSigned": true, "logoutRequestSigned": false, "wantNameIdEncrypted": false, "logoutResponseSigned": false, "wantAssertionsSigned": true, "putMetadataValidUntil": false, "requestedAuthnContext": ["urn:oasis:names:tc:SAML:2.0:ac:classes:SpidL1"], "wantAttributeStatement": true, "wantAssertionsEncrypted": true, "putMetadataCacheDuration": false, "requestedAuthnContextComparison": "minimum"}, "organization": {"it": {"url": "http://www.uniroma1.it", "name": "Universita'' Sapienza", "displayname": "Universita'' degli Studi La Sapienza - Roma"}}, "contactPerson": {"support": {"givenName": "InfoSapienza", "emailAddress": "infostud@uniroma1.it"}, "technical": {"givenName": "InfoSapienza", "emailAddress": "infostud@uniroma1.it"}}}', '2017-06-09 17:44:19.182224+02', NULL);

--
-- TOC entry 2827 (class 0 OID 0)
-- Dependencies: 214
-- Name: settings_ID_seq; Type: SEQUENCE SET; Schema: saml; Owner: -
--

SELECT pg_catalog.setval('"settings_ID_seq"', 2, true);


--
-- TOC entry 2775 (class 0 OID 33855)
-- Dependencies: 205
-- Data for Name: signatures; Type: TABLE DATA; Schema: saml; Owner: -
--

INSERT INTO signatures ("ID", cod_cert, private_key, public_key, cod_provider, date, fingerprint, fingerprintalg) VALUES (8, 'cert_pt', NULL, '-----BEGIN CERTIFICATE-----
MIIEKzCCAxOgAwIBAgIDE2Y0MA0GCSqGSIb3DQEBCwUAMGAxCzAJBgNVBAYTAklU
MRgwFgYDVQQKDA9Qb3N0ZWNvbSBTLnAuQS4xIDAeBgNVBAsMF0NlcnRpZmljYXRp
b24gQXV0aG9yaXR5MRUwEwYDVQQDDAxQb3N0ZWNvbSBDQTMwHhcNMTYwMjI2MTU1
MjQ0WhcNMjEwMjI2MTU1MjQ0WjBxMQswCQYDVQQGEwJJVDEOMAwGA1UECAwFSXRh
bHkxDTALBgNVBAcMBFJvbWUxHjAcBgNVBAoMFVBvc3RlIEl0YWxpYW5lIFMucC5B
LjENMAsGA1UECwwEU1BJRDEUMBIGA1UEAwwLSURQLVBvc3RlSUQwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDZFEtJoEHFAjpCaZcj5DVWrRDyaLZyu31X
Apslbo87CyWz61OJMtw6QQU0MdCtrYbtSJ6vJwx7/6EUjsZ3u4x3EPLdlkyiGOqu
kPwATv4c7TVOUVs5onIqTphM9b+AHRg4ehiMGesm/9d7RIaLuN79iPUvdLn6WP3i
dAfEw+rhJ/wYEQ0h1Xm5osNUgtWcBGavZIjLssWNrDDfJYxXH3QZ0kI6feEvLCJw
gjXLGkBuhFehNhM4fhbX9iUCWwwkJ3JsP2++Rc/iTA0LZhiUsXNNq7gBcLAJ9UX2
V1dWjTzBHevfHspzt4e0VgIIwbDRqsRtF8VUPSDYYbLoqwbLt18XAgMBAAGjgdww
gdkwRgYDVR0gBD8wPTAwBgcrTAsBAgEBMCUwIwYIKwYBBQUHAgEWF2h0dHA6Ly93
d3cucG9zdGVjZXJ0Lml0MAkGBytMCwEBCgIwDgYDVR0PAQH/BAQDAgSwMB8GA1Ud
IwQYMBaAFKc0XP2FByYU2l0gFzGKE8zVSzfmMD8GA1UdHwQ4MDYwNKAyoDCGLmh0
dHA6Ly9wb3N0ZWNlcnQucG9zdGUuaXQvcG9zdGVjb21jYTMvY3JsMy5jcmwwHQYD
VR0OBBYEFEvrikZQkfBjuiTpxExSBe8wGgsyMA0GCSqGSIb3DQEBCwUAA4IBAQBN
Aw8UoeiCF+1rFs27d3bEef6CLe/PJga9EfwKItjMDD9QzT/FShRWKLHlK69MHL1Z
LPRPvuWUTkIOHTpNqBPILvO1u13bSg+6o+2OdqAkCBkbTqbGjWSPLaTUVNV6MbXm
vttD8Vd9vIZg1xBBG3Fai13dwvSj3hAZd8ug8a8fW1y/iDbRC5D1O+HlHDuvIW4L
bJ093jdj+oZwSyd216gtXL00QA0C1uMuDv9Wf9IxniTb710dRSgIcM4/eR7832fZ
gdOsoalFzGYWxSCs8WOZrjpub1fdaRSEuCQk2+gmdsiRcTs9EqPCCNiNlrNAiWEy
GtL8A4ao3pDMwCtrb2yr
-----END CERTIFICATE-----
', 'pt', '2017-06-03 11:55:43.400558+02', 'ab1bf09a9bcaeb1e8a243bc7f98de4325c066754', 'sha1');
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
INSERT INTO signatures ("ID", cod_cert, private_key, public_key, cod_provider, date, fingerprint, fingerprintalg) VALUES (9, 'cert_aruba', NULL, '-----BEGIN CERTIFICATE-----MIIExTCCA62gAwIBAgIQIHtEvEhGM77HwqsuvSbi9zANBgkqhkiG9w0BAQsFADBsMQswCQYDVQQGEwJJVDEYMBYGA1UECgwPQXJ1YmFQRUMgUy5wLkEuMSEwHwYDVQQLDBhDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eUIxIDAeBgNVBAMMF0FydWJhUEVDIFMucC5BLiBORyBDQSAyMB4XDTE3MDEyMzAwMDAwMFoXDTIwMDEyMzIzNTk1OVowgaAxCzAJBgNVBAYTAklUMRYwFAYDVQQKDA1BcnViYSBQRUMgc3BhMREwDwYDVQQLDAhQcm9kb3R0bzEWMBQGA1UEAwwNcGVjLml0IHBlYy5pdDEZMBcGA1UEBRMQWFhYWFhYMDBYMDBYMDAwWDEPMA0GA1UEKgwGcGVjLml0MQ8wDQYDVQQEDAZwZWMuaXQxETAPBgNVBC4TCDE2MzQ1MzgzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqt2oHJhcp03l73p+QYpEJ+f3jYYj0W0gos0RItZx/w4vpsiKBygaqDNVWSwfo1aPdVDIX13f62O+lBki29KTt+QWv5K6SGHDUXYPntRdEQlicIBh2Z0HfrM7fDl+xeJrMp1s4dsSQAuB5TJOlFZq7xCQuukytGWBTvjfcN/os5aEsEg+RbtZHJR26SbbUcIqWb27Swgj/9jwK+tvzLnP4w8FNvEOrNfR0XwTMNDFrwbOCuWgthv5jNBsVZaoqNwiA/MxYt+gTOMj/o5PWKk8Wpm6o/7/+lWAoxh0v8x9OkbIi+YaFpIxuCcUqsrJJk63x2gHCc2nr+yclYUhsKD/AwIDAQABo4IBLDCCASgwDgYDVR0PAQH/BAQDAgeAMB0GA1UdDgQWBBTKQ3+NPGcXFk8nX994vMTVpba1EzBHBgNVHSAEQDA+MDwGCysGAQQBgegtAQEBMC0wKwYIKwYBBQUHAgEWH2h0dHBzOi8vY2EuYXJ1YmFwZWMuaXQvY3BzLmh0bWwwWAYDVR0fBFEwTzBNoEugSYZHaHR0cDovL2NybC5hcnViYXBlYy5pdC9BcnViYVBFQ1NwQUNlcnRpZmljYXRpb25BdXRob3JpdHlCL0xhdGVzdENSTC5jcmwwHwYDVR0jBBgwFoAU8v9jQBwRQv3M3/FZ9m7omYcxR3kwMwYIKwYBBQUHAQEEJzAlMCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5hcnViYXBlYy5pdDANBgkqhkiG9w0BAQsFAAOCAQEAnEw0NuaspbpDjA5wggwFtfQydU6b3Bw2/KXPRKS2JoqGmx0SYKj+L17A2KUBa2c7gDtKXYz0FLT60Bv0pmBN/oYCgVMEBJKqwRwdki9YjEBwyCZwNEx1kDAyyqFEVU9vw/OQfrAdp7MTbuZGFKknVt7b9wOYy/Op9FiUaTg6SuOy0ep+rqhihltYNAAl4L6fY45mHvqa5vvVG30OvLW/S4uvRYUXYwY6KhWvNdDf5CnFugnuEZtHJrVe4wx9aO5GvFLFZ/mQ35C5mXPQ7nIb0CDdLBJdz82nUoLSA5BUbeXAUkfahW/hLxLdhks68/TK694xVIuiB40pvMmJwxIyDA==-----END CERTIFICATE-----', 'aruba', '2017-06-09 16:57:28.503129+02', 'a6ebf358fa4b276cac5622459486a92c88dc1c37', 'sha1');
INSERT INTO signatures ("ID", cod_cert, private_key, public_key, cod_provider, date, fingerprint, fingerprintalg) VALUES (11, 'cert_infocrt', NULL, '-----BEGIN CERTIFICATE-----MIIGbDCCBVSgAwIBAgIDA+76MA0GCSqGSIb3DQEBCwUAMIGGMQswCQYDVQQGEwJJVDEVMBMGA1UECgwMSU5GT0NFUlQgU1BBMRswGQYDVQQLDBJFbnRlIENlcnRpZmljYXRvcmUxFDASBgNVBAUTCzA3OTQ1MjExMDA2MS0wKwYDVQQDDCRJbmZvQ2VydCBTZXJ2aXppIGRpIENlcnRpZmljYXppb25lIDIwHhcNMTYwMTEyMDkyNDI4WhcNMTkwMTEyMDAwMDAwWjCBsTEUMBIGA1UELhMLMDc5NDUyMTEwMDYxDzANBgkqhkiG9w0BCQEWADEUMBIGA1UEBRMLMDc5NDUyMTEwMDYxHTAbBgNVBAMMFGlkZW50aXR5LmluZm9jZXJ0Lml0MRQwEgYDVQQLDAtJbmZvQ2VydCBJRDEhMB8GA1UECgwYSW5mb0NlcnQgU3BBLzA3OTQ1MjExMDA2MQ0wCwYDVQQHDARSb21hMQswCQYDVQQGEwJJVDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALDysrpnXB+it94LSuAmOgyFDilZ8nuSEVOFl1PX/HtgK3W25B/tqJBsyZwrAIXxg5XHYd3+i7bFoBjuduzfqhvSv9WYCVtggsz5a3sbOpU54DaOLgoCmd4nIsINwKzCmT1UNXBGjS+Xt5F3lV+v2Ayr4rAsPnkE2084BLmwcIX3w7+rx/Nd+/5HfaAMaORICYinUIvbZ5e/plUj87s1YEpep/DcC0uMFE66jFrcnHVOeHCrDh+tAZAiGew4BVJjLr0hfS4ZeaE43TJlHb00GZNfpfzGcOPbzWlSB5iF/cZbTRHmPsn0gALfpPNViniFBVqSaoywZwvkFosrehRUCNkCAwEAAaOCArQwggKwMBMGA1UdJQQMMAoGCCsGAQUFBwMCMCUGA1UdEgQeMByBGmZpcm1hLmRpZ2l0YWxlQGluZm9jZXJ0Lml0MGUGA1UdIAReMFwwWgYGK0wkAQEIMFAwTgYIKwYBBQUHAgIwQgxASW5mb0NlcnQgU3BBIFNTTCwgU01JTUUgYW5kIGRpZ2l0YWwgc2lnbmF0dXJlIENsaWVudCBDZXJ0aWZpY2F0ZTA3BggrBgEFBQcBAQQrMCkwJwYIKwYBBQUHMAGGG2h0dHA6Ly9vY3NwLnNjLmluZm9jZXJ0Lml0LzCB7AYDVR0fBIHkMIHhMDSgMqAwhi5odHRwOi8vY3JsLmluZm9jZXJ0Lml0L2NybHMvc2Vydml6aTIvQ1JMMDEuY3JsMIGooIGloIGihoGfbGRhcDovL2xkYXAuaW5mb2NlcnQuaXQvY24lM0RJbmZvQ2VydCUyMFNlcnZpemklMjBkaSUyMENlcnRpZmljYXppb25lJTIwMiUyMENSTDAxLG91JTNERW50ZSUyMENlcnRpZmljYXRvcmUsbyUzRElORk9DRVJUJTIwU1BBLEMlM0RJVD9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0MA4GA1UdDwEB/wQEAwIEsDCBswYDVR0jBIGrMIGogBTpNppkKVKhWv5ppMSDt4B9D2oSeKGBjKSBiTCBhjELMAkGA1UEBhMCSVQxFTATBgNVBAoMDElORk9DRVJUIFNQQTEbMBkGA1UECwwSRW50ZSBDZXJ0aWZpY2F0b3JlMRQwEgYDVQQFEwswNzk0NTIxMTAwNjEtMCsGA1UEAwwkSW5mb0NlcnQgU2Vydml6aSBkaSBDZXJ0aWZpY2F6aW9uZSAyggECMB0GA1UdDgQWBBTi8mIRU4ue/0lKSfv4gSQhoZQvozANBgkqhkiG9w0BAQsFAAOCAQEAUCXyjmfzxmyVQbK4cf79zj5qMZVAAjDMTR1UGFcS2IibICh3S3Uf22lPGQfm+MX9tiweETW7fBLW6lrR2ofXBz/FfU98A/AA9GZDrbGhBxoc+RoqkHVYRqEuXOq6z3X9DuvsdsfKeO3p4eXbXlCcxD2PP5fFqcZxx1WZ1HRamiGk9fMN1iT3aPa3q7TfRD6W6+XgafjXieZ8bCa1FGIfapbqsWa91jdn4xiJpbmTTq1/Zjs5RCZYzmMEV9rSuSVgFtONb8+xKC4ohMVxAUw2yZHwd4dDyBLkapuaWkzhW939+gjeoKz04Ds2C52d/kln7ehdu9LkzvRI6UAEpAYLgg==-----END CERTIFICATE-----', 'infocrt', '2017-06-15 17:37:37.213463+02', '338d25e8ee81f1279a37c89ce013a3640b413c28', 'sha1');


SET search_path = jwt, pg_catalog;

--
-- TOC entry 2537 (class 2606 OID 24589)
-- Name: token token_cod_key; Type: CONSTRAINT; Schema: jwt; Owner: -
--

ALTER TABLE ONLY token
    ADD CONSTRAINT token_cod_key UNIQUE (cod_token);


--
-- TOC entry 2559 (class 2606 OID 32900)
-- Name: token_payload token_payload_cod_payload_key; Type: CONSTRAINT; Schema: jwt; Owner: -
--

ALTER TABLE ONLY token_payload
    ADD CONSTRAINT token_payload_cod_payload_key UNIQUE (cod_payload);


--
-- TOC entry 2561 (class 2606 OID 32898)
-- Name: token_payload token_payload_pkey; Type: CONSTRAINT; Schema: jwt; Owner: -
--

ALTER TABLE ONLY token_payload
    ADD CONSTRAINT token_payload_pkey PRIMARY KEY ("ID");


--
-- TOC entry 2541 (class 2606 OID 24587)
-- Name: token token_pkey; Type: CONSTRAINT; Schema: jwt; Owner: -
--

ALTER TABLE ONLY token
    ADD CONSTRAINT token_pkey PRIMARY KEY ("ID");


--
-- TOC entry 2545 (class 2606 OID 24618)
-- Name: token_schemas token_schemas_cod_schema_key; Type: CONSTRAINT; Schema: jwt; Owner: -
--

ALTER TABLE ONLY token_schemas
    ADD CONSTRAINT token_schemas_cod_schema_key UNIQUE (cod_schema);


--
-- TOC entry 2547 (class 2606 OID 24616)
-- Name: token_schemas token_schemas_pkey; Type: CONSTRAINT; Schema: jwt; Owner: -
--

ALTER TABLE ONLY token_schemas
    ADD CONSTRAINT token_schemas_pkey PRIMARY KEY ("ID");


--
-- TOC entry 2555 (class 2606 OID 32819)
-- Name: token_signature token_signature_cod_signature_key; Type: CONSTRAINT; Schema: jwt; Owner: -
--

ALTER TABLE ONLY token_signature
    ADD CONSTRAINT token_signature_cod_signature_key UNIQUE (cod_signature);


--
-- TOC entry 2557 (class 2606 OID 32817)
-- Name: token_signature token_signature_pkey; Type: CONSTRAINT; Schema: jwt; Owner: -
--

ALTER TABLE ONLY token_signature
    ADD CONSTRAINT token_signature_pkey PRIMARY KEY ("ID");


--
-- TOC entry 2551 (class 2606 OID 32799)
-- Name: token_type token_type_pk; Type: CONSTRAINT; Schema: jwt; Owner: -
--

ALTER TABLE ONLY token_type
    ADD CONSTRAINT token_type_pk PRIMARY KEY ("ID");


--
-- TOC entry 2553 (class 2606 OID 32801)
-- Name: token_type token_type_un; Type: CONSTRAINT; Schema: jwt; Owner: -
--

ALTER TABLE ONLY token_type
    ADD CONSTRAINT token_type_un UNIQUE (cod_type);


SET search_path = saml, pg_catalog;

--
-- TOC entry 2575 (class 2606 OID 42117)
-- Name: assertions assertions_ID_assertion_key; Type: CONSTRAINT; Schema: saml; Owner: -
--

ALTER TABLE ONLY assertions
    ADD CONSTRAINT "assertions_ID_assertion_key" UNIQUE ("ID_assertion");


--
-- TOC entry 2578 (class 2606 OID 33888)
-- Name: assertions assertions_cod_assertion_key; Type: CONSTRAINT; Schema: saml; Owner: -
--

ALTER TABLE ONLY assertions
    ADD CONSTRAINT assertions_cod_assertion_key UNIQUE (cod_assertion);


--
-- TOC entry 2580 (class 2606 OID 33886)
-- Name: assertions assertions_pkey; Type: CONSTRAINT; Schema: saml; Owner: -
--

ALTER TABLE ONLY assertions
    ADD CONSTRAINT assertions_pkey PRIMARY KEY ("ID");


--
-- TOC entry 2582 (class 2606 OID 33976)
-- Name: assertions_type assertions_type_cod_type_key; Type: CONSTRAINT; Schema: saml; Owner: -
--

ALTER TABLE ONLY assertions_type
    ADD CONSTRAINT assertions_type_cod_type_key UNIQUE (cod_type);


--
-- TOC entry 2584 (class 2606 OID 33974)
-- Name: assertions_type assertions_type_pkey; Type: CONSTRAINT; Schema: saml; Owner: -
--

ALTER TABLE ONLY assertions_type
    ADD CONSTRAINT assertions_type_pkey PRIMARY KEY ("ID");


--
-- TOC entry 2570 (class 2606 OID 33866)
-- Name: signatures certifcates_cod_cert_key; Type: CONSTRAINT; Schema: saml; Owner: -
--

ALTER TABLE ONLY signatures
    ADD CONSTRAINT certifcates_cod_cert_key UNIQUE (cod_cert);


--
-- TOC entry 2572 (class 2606 OID 33864)
-- Name: signatures certifcates_pkey; Type: CONSTRAINT; Schema: saml; Owner: -
--

ALTER TABLE ONLY signatures
    ADD CONSTRAINT certifcates_pkey PRIMARY KEY ("ID");


--
-- TOC entry 2607 (class 2606 OID 42300)
-- Name: jwt_settings jwt_settings_cod_jwt_setting_key; Type: CONSTRAINT; Schema: saml; Owner: -
--

ALTER TABLE ONLY jwt_settings
    ADD CONSTRAINT jwt_settings_cod_jwt_setting_key UNIQUE (cod_jwt_setting);


--
-- TOC entry 2609 (class 2606 OID 42297)
-- Name: jwt_settings jwt_settings_pkey; Type: CONSTRAINT; Schema: saml; Owner: -
--

ALTER TABLE ONLY jwt_settings
    ADD CONSTRAINT jwt_settings_pkey PRIMARY KEY ("ID");


--
-- TOC entry 2591 (class 2606 OID 34644)
-- Name: metadata metadata_active_cod_provider_key; Type: CONSTRAINT; Schema: saml; Owner: -
--

ALTER TABLE ONLY metadata
    ADD CONSTRAINT metadata_active_cod_provider_key UNIQUE (active, cod_provider);


--
-- TOC entry 2594 (class 2606 OID 34642)
-- Name: metadata metadata_cod_metadata_key; Type: CONSTRAINT; Schema: saml; Owner: -
--

ALTER TABLE ONLY metadata
    ADD CONSTRAINT metadata_cod_metadata_key UNIQUE (cod_metadata);


--
-- TOC entry 2597 (class 2606 OID 34640)
-- Name: metadata metadata_pkey; Type: CONSTRAINT; Schema: saml; Owner: -
--

ALTER TABLE ONLY metadata
    ADD CONSTRAINT metadata_pkey PRIMARY KEY ("ID");


--
-- TOC entry 2564 (class 2606 OID 33850)
-- Name: providers providers_cod_provider_key; Type: CONSTRAINT; Schema: saml; Owner: -
--

ALTER TABLE ONLY providers
    ADD CONSTRAINT providers_cod_provider_key UNIQUE (cod_provider);


--
-- TOC entry 2567 (class 2606 OID 33848)
-- Name: providers providers_pkey; Type: CONSTRAINT; Schema: saml; Owner: -
--

ALTER TABLE ONLY providers
    ADD CONSTRAINT providers_pkey PRIMARY KEY ("ID");


--
-- TOC entry 2586 (class 2606 OID 34005)
-- Name: services services_cod_service_key; Type: CONSTRAINT; Schema: saml; Owner: -
--

ALTER TABLE ONLY services
    ADD CONSTRAINT services_cod_service_key UNIQUE (cod_service);


--
-- TOC entry 2589 (class 2606 OID 34003)
-- Name: services services_pkey; Type: CONSTRAINT; Schema: saml; Owner: -
--

ALTER TABLE ONLY services
    ADD CONSTRAINT services_pkey PRIMARY KEY ("ID");


--
-- TOC entry 2599 (class 2606 OID 42099)
-- Name: settings setting_active_cod_provider_key; Type: CONSTRAINT; Schema: saml; Owner: -
--

ALTER TABLE ONLY settings
    ADD CONSTRAINT setting_active_cod_provider_key UNIQUE (active, cod_provider);


--
-- TOC entry 2603 (class 2606 OID 42101)
-- Name: settings setting_cod_setting_key; Type: CONSTRAINT; Schema: saml; Owner: -
--

ALTER TABLE ONLY settings
    ADD CONSTRAINT setting_cod_setting_key UNIQUE (cod_setting);


--
-- TOC entry 2605 (class 2606 OID 42097)
-- Name: settings setting_pkey; Type: CONSTRAINT; Schema: saml; Owner: -
--

ALTER TABLE ONLY settings
    ADD CONSTRAINT setting_pkey PRIMARY KEY ("ID");


SET search_path = jwt, pg_catalog;

--
-- TOC entry 2535 (class 1259 OID 32830)
-- Name: fki_token_token_type_fk; Type: INDEX; Schema: jwt; Owner: -
--

CREATE INDEX fki_token_token_type_fk ON token USING btree (cod_type);


--
-- TOC entry 2538 (class 1259 OID 24591)
-- Name: token_header_idx; Type: INDEX; Schema: jwt; Owner: -
--

CREATE INDEX token_header_idx ON token USING btree (header);


--
-- TOC entry 2539 (class 1259 OID 24592)
-- Name: token_payload_idx; Type: INDEX; Schema: jwt; Owner: -
--

CREATE INDEX token_payload_idx ON token USING btree (payload);


--
-- TOC entry 2543 (class 1259 OID 24621)
-- Name: token_schemas_active_idx; Type: INDEX; Schema: jwt; Owner: -
--

CREATE INDEX token_schemas_active_idx ON token_schemas USING btree (active);


--
-- TOC entry 2548 (class 1259 OID 24620)
-- Name: token_schemas_schema_idx; Type: INDEX; Schema: jwt; Owner: -
--

CREATE INDEX token_schemas_schema_idx ON token_schemas USING btree (schema);


--
-- TOC entry 2549 (class 1259 OID 24619)
-- Name: token_schemas_type_idx; Type: INDEX; Schema: jwt; Owner: -
--

CREATE INDEX token_schemas_type_idx ON token_schemas USING btree (cod_type);


--
-- TOC entry 2542 (class 1259 OID 24590)
-- Name: token_token_idx; Type: INDEX; Schema: jwt; Owner: -
--

CREATE INDEX token_token_idx ON token USING btree (token);


SET search_path = saml, pg_catalog;

--
-- TOC entry 2576 (class 1259 OID 42352)
-- Name: assertions_ID_response_assertion_idx; Type: INDEX; Schema: saml; Owner: -
--

CREATE INDEX "assertions_ID_response_assertion_idx" ON assertions USING btree ("ID_response_assertion");


--
-- TOC entry 2592 (class 1259 OID 34650)
-- Name: metadata_cod_metadata_idx; Type: INDEX; Schema: saml; Owner: -
--

CREATE INDEX metadata_cod_metadata_idx ON metadata USING btree (cod_metadata bpchar_pattern_ops);


--
-- TOC entry 2595 (class 1259 OID 34651)
-- Name: metadata_cod_provider_idx; Type: INDEX; Schema: saml; Owner: -
--

CREATE INDEX metadata_cod_provider_idx ON metadata USING btree (cod_provider);


--
-- TOC entry 2562 (class 1259 OID 33852)
-- Name: providers_active_idx; Type: INDEX; Schema: saml; Owner: -
--

CREATE INDEX providers_active_idx ON providers USING btree (active);


--
-- TOC entry 2565 (class 1259 OID 33956)
-- Name: providers_name_idx; Type: INDEX; Schema: saml; Owner: -
--

CREATE INDEX providers_name_idx ON providers USING btree (name);


--
-- TOC entry 2568 (class 1259 OID 33851)
-- Name: providers_type_idx; Type: INDEX; Schema: saml; Owner: -
--

CREATE INDEX providers_type_idx ON providers USING btree (type);


--
-- TOC entry 2587 (class 1259 OID 34011)
-- Name: services_name_idx; Type: INDEX; Schema: saml; Owner: -
--

CREATE INDEX services_name_idx ON services USING btree (name);


--
-- TOC entry 2600 (class 1259 OID 42108)
-- Name: setting_cod_provider_idx; Type: INDEX; Schema: saml; Owner: -
--

CREATE INDEX setting_cod_provider_idx ON settings USING btree (cod_provider DESC);


--
-- TOC entry 2601 (class 1259 OID 42107)
-- Name: setting_cod_setting_idx; Type: INDEX; Schema: saml; Owner: -
--

CREATE INDEX setting_cod_setting_idx ON settings USING btree (cod_setting DESC);


--
-- TOC entry 2573 (class 1259 OID 42043)
-- Name: signatures_fingerprint_idx; Type: INDEX; Schema: saml; Owner: -
--

CREATE INDEX signatures_fingerprint_idx ON signatures USING btree (fingerprint);


SET search_path = jwt, pg_catalog;

--
-- TOC entry 2626 (class 2620 OID 32938)
-- Name: token 01_chk_token_header_insert; Type: TRIGGER; Schema: jwt; Owner: -
--

CREATE TRIGGER "01_chk_token_header_insert" BEFORE INSERT ON token FOR EACH ROW EXECUTE PROCEDURE header_validator();


--
-- TOC entry 2631 (class 2620 OID 32942)
-- Name: token_signature 01_chk_token_header_insert; Type: TRIGGER; Schema: jwt; Owner: -
--

CREATE TRIGGER "01_chk_token_header_insert" BEFORE INSERT ON token_signature FOR EACH ROW EXECUTE PROCEDURE header_validator();


--
-- TOC entry 2627 (class 2620 OID 32939)
-- Name: token 01_chk_token_header_update; Type: TRIGGER; Schema: jwt; Owner: -
--

CREATE TRIGGER "01_chk_token_header_update" BEFORE UPDATE ON token FOR EACH ROW WHEN ((old.header IS DISTINCT FROM new.header)) EXECUTE PROCEDURE header_validator();


--
-- TOC entry 2632 (class 2620 OID 32943)
-- Name: token_signature 01_chk_token_header_update; Type: TRIGGER; Schema: jwt; Owner: -
--

CREATE TRIGGER "01_chk_token_header_update" BEFORE UPDATE ON token_signature FOR EACH ROW WHEN ((old.header IS DISTINCT FROM new.header)) EXECUTE PROCEDURE header_validator();


--
-- TOC entry 2630 (class 2620 OID 33824)
-- Name: token_schemas 01_token_schemas_update; Type: TRIGGER; Schema: jwt; Owner: -
--

CREATE TRIGGER "01_token_schemas_update" BEFORE UPDATE ON token_schemas FOR EACH ROW EXECUTE PROCEDURE schemas_validator();


--
-- TOC entry 2628 (class 2620 OID 32940)
-- Name: token 02_chk_token_payload_insert; Type: TRIGGER; Schema: jwt; Owner: -
--

CREATE TRIGGER "02_chk_token_payload_insert" BEFORE INSERT ON token FOR EACH ROW EXECUTE PROCEDURE payload_validator();


--
-- TOC entry 2633 (class 2620 OID 32944)
-- Name: token_payload 02_chk_token_payload_insert; Type: TRIGGER; Schema: jwt; Owner: -
--

CREATE TRIGGER "02_chk_token_payload_insert" BEFORE INSERT ON token_payload FOR EACH ROW EXECUTE PROCEDURE payload_validator();


--
-- TOC entry 2629 (class 2620 OID 32941)
-- Name: token 02_chk_token_payload_update; Type: TRIGGER; Schema: jwt; Owner: -
--

CREATE TRIGGER "02_chk_token_payload_update" BEFORE UPDATE ON token FOR EACH ROW WHEN ((old.payload IS DISTINCT FROM new.payload)) EXECUTE PROCEDURE payload_validator();


--
-- TOC entry 2634 (class 2620 OID 32945)
-- Name: token_payload 02_chk_token_payload_update; Type: TRIGGER; Schema: jwt; Owner: -
--

CREATE TRIGGER "02_chk_token_payload_update" BEFORE UPDATE ON token_payload FOR EACH ROW WHEN ((old.payload IS DISTINCT FROM new.payload)) EXECUTE PROCEDURE payload_validator();


SET search_path = saml, pg_catalog;

--
-- TOC entry 2635 (class 2620 OID 33962)
-- Name: providers 01_date_update; Type: TRIGGER; Schema: saml; Owner: -
--

CREATE TRIGGER "01_date_update" BEFORE UPDATE ON providers FOR EACH ROW EXECUTE PROCEDURE get_current_timestamp();


--
-- TOC entry 2636 (class 2620 OID 33963)
-- Name: signatures 01_date_update; Type: TRIGGER; Schema: saml; Owner: -
--

CREATE TRIGGER "01_date_update" BEFORE UPDATE ON signatures FOR EACH ROW EXECUTE PROCEDURE get_current_timestamp();


--
-- TOC entry 2638 (class 2620 OID 33964)
-- Name: assertions 01_date_update; Type: TRIGGER; Schema: saml; Owner: -
--

CREATE TRIGGER "01_date_update" BEFORE UPDATE ON assertions FOR EACH ROW EXECUTE PROCEDURE get_current_timestamp();


--
-- TOC entry 2640 (class 2620 OID 34652)
-- Name: metadata 01_date_update; Type: TRIGGER; Schema: saml; Owner: -
--

CREATE TRIGGER "01_date_update" BEFORE UPDATE ON metadata FOR EACH ROW EXECUTE PROCEDURE get_current_timestamp();


--
-- TOC entry 2641 (class 2620 OID 42109)
-- Name: settings 01_date_update; Type: TRIGGER; Schema: saml; Owner: -
--

CREATE TRIGGER "01_date_update" BEFORE UPDATE ON settings FOR EACH ROW EXECUTE PROCEDURE get_current_timestamp();


--
-- TOC entry 2639 (class 2620 OID 42136)
-- Name: assertions 02_ID_assertion_update; Type: TRIGGER; Schema: saml; Owner: -
--

CREATE TRIGGER "02_ID_assertion_update" BEFORE INSERT OR UPDATE ON assertions FOR EACH ROW EXECUTE PROCEDURE assertions();


--
-- TOC entry 2637 (class 2620 OID 42036)
-- Name: signatures 02_fingerprint_update; Type: TRIGGER; Schema: saml; Owner: -
--

CREATE TRIGGER "02_fingerprint_update" BEFORE INSERT OR UPDATE ON signatures FOR EACH ROW EXECUTE PROCEDURE get_x509_fingerprint();


SET search_path = jwt, pg_catalog;

--
-- TOC entry 2613 (class 2606 OID 32901)
-- Name: token_payload token_payload_cod_type_fkey; Type: FK CONSTRAINT; Schema: jwt; Owner: -
--

ALTER TABLE ONLY token_payload
    ADD CONSTRAINT token_payload_cod_type_fkey FOREIGN KEY (cod_type) REFERENCES token_type(cod_type) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- TOC entry 2611 (class 2606 OID 32831)
-- Name: token_schemas token_schemas_token_type_fk; Type: FK CONSTRAINT; Schema: jwt; Owner: -
--

ALTER TABLE ONLY token_schemas
    ADD CONSTRAINT token_schemas_token_type_fk FOREIGN KEY (cod_type) REFERENCES token_type(cod_type) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- TOC entry 2612 (class 2606 OID 32820)
-- Name: token_signature token_signature_cod_type_fkey; Type: FK CONSTRAINT; Schema: jwt; Owner: -
--

ALTER TABLE ONLY token_signature
    ADD CONSTRAINT token_signature_cod_type_fkey FOREIGN KEY (cod_type) REFERENCES token_type(cod_type) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- TOC entry 2610 (class 2606 OID 32825)
-- Name: token token_token_type_fk; Type: FK CONSTRAINT; Schema: jwt; Owner: -
--

ALTER TABLE ONLY token
    ADD CONSTRAINT token_token_type_fk FOREIGN KEY (cod_type) REFERENCES token_type(cod_type) ON UPDATE CASCADE ON DELETE RESTRICT;


SET search_path = saml, pg_catalog;

--
-- TOC entry 2619 (class 2606 OID 42273)
-- Name: assertions assertions_cod_idp_fkey; Type: FK CONSTRAINT; Schema: saml; Owner: -
--

ALTER TABLE ONLY assertions
    ADD CONSTRAINT assertions_cod_idp_fkey FOREIGN KEY (cod_idp) REFERENCES providers(cod_provider) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- TOC entry 2618 (class 2606 OID 42268)
-- Name: assertions assertions_cod_sp_fkey; Type: FK CONSTRAINT; Schema: saml; Owner: -
--

ALTER TABLE ONLY assertions
    ADD CONSTRAINT assertions_cod_sp_fkey FOREIGN KEY (cod_sp) REFERENCES providers(cod_provider) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- TOC entry 2615 (class 2606 OID 33889)
-- Name: assertions assertions_cod_token_fkey; Type: FK CONSTRAINT; Schema: saml; Owner: -
--

ALTER TABLE ONLY assertions
    ADD CONSTRAINT assertions_cod_token_fkey FOREIGN KEY (cod_token) REFERENCES jwt.token(cod_token) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- TOC entry 2616 (class 2606 OID 33977)
-- Name: assertions assertions_cod_type_fkey; Type: FK CONSTRAINT; Schema: saml; Owner: -
--

ALTER TABLE ONLY assertions
    ADD CONSTRAINT assertions_cod_type_fkey FOREIGN KEY (cod_type) REFERENCES assertions_type(cod_type) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- TOC entry 2617 (class 2606 OID 42263)
-- Name: assertions assertions_providers_fk; Type: FK CONSTRAINT; Schema: saml; Owner: -
--

ALTER TABLE ONLY assertions
    ADD CONSTRAINT assertions_providers_fk FOREIGN KEY (cod_sp) REFERENCES providers(cod_provider) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- TOC entry 2614 (class 2606 OID 33867)
-- Name: signatures certifcates_cod_provider_fkey; Type: FK CONSTRAINT; Schema: saml; Owner: -
--

ALTER TABLE ONLY signatures
    ADD CONSTRAINT certifcates_cod_provider_fkey FOREIGN KEY (cod_provider) REFERENCES providers(cod_provider) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- TOC entry 2624 (class 2606 OID 42306)
-- Name: jwt_settings jwt_settings_cod_provider_fkey; Type: FK CONSTRAINT; Schema: saml; Owner: -
--

ALTER TABLE ONLY jwt_settings
    ADD CONSTRAINT jwt_settings_cod_provider_fkey FOREIGN KEY (cod_provider) REFERENCES providers(cod_provider) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- TOC entry 2623 (class 2606 OID 42311)
-- Name: jwt_settings jwt_settings_cod_type_assertion_fkey; Type: FK CONSTRAINT; Schema: saml; Owner: -
--

ALTER TABLE ONLY jwt_settings
    ADD CONSTRAINT jwt_settings_cod_type_assertion_fkey FOREIGN KEY (cod_type_assertion) REFERENCES assertions_type(cod_type) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- TOC entry 2625 (class 2606 OID 42301)
-- Name: jwt_settings jwt_settings_cod_type_token_fkey; Type: FK CONSTRAINT; Schema: saml; Owner: -
--

ALTER TABLE ONLY jwt_settings
    ADD CONSTRAINT jwt_settings_cod_type_token_fkey FOREIGN KEY (cod_type_token) REFERENCES jwt.token_type(cod_type) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- TOC entry 2621 (class 2606 OID 34645)
-- Name: metadata metadata_cod_provider_fkey; Type: FK CONSTRAINT; Schema: saml; Owner: -
--

ALTER TABLE ONLY metadata
    ADD CONSTRAINT metadata_cod_provider_fkey FOREIGN KEY (cod_provider) REFERENCES providers(cod_provider) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- TOC entry 2620 (class 2606 OID 34006)
-- Name: services services_cod_provider_fkey; Type: FK CONSTRAINT; Schema: saml; Owner: -
--

ALTER TABLE ONLY services
    ADD CONSTRAINT services_cod_provider_fkey FOREIGN KEY (cod_provider) REFERENCES providers(cod_provider) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- TOC entry 2622 (class 2606 OID 42102)
-- Name: settings setting_cod_provider_fkey; Type: FK CONSTRAINT; Schema: saml; Owner: -
--

ALTER TABLE ONLY settings
    ADD CONSTRAINT setting_cod_provider_fkey FOREIGN KEY (cod_provider) REFERENCES providers(cod_provider) ON UPDATE CASCADE ON DELETE RESTRICT;


-- Completed on 2017-07-14 07:14:38 CEST

--
-- PostgreSQL database dump complete
--

