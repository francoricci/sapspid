from onelogin.saml2.errors import OneLogin_Saml2_Error
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.metadata import OneLogin_Saml2_Metadata
from easyspid.lib.metadata import MetaDataBuilder
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.utils import OneLogin_Saml2_XML
from onelogin.saml2.utils import OneLogin_Saml2_Utils, return_false_on_exception
from onelogin.saml2.response import OneLogin_Saml2_Response
from onelogin.saml2.errors import OneLogin_Saml2_ValidationError
import easyspid.lib.easyspid
import xml.etree.ElementTree
from lxml import etree
from onelogin.saml2 import compat
import re
import asyncio
import globalsObj
import time
import xmlsec
import os
import jsonpickle

class Saml2_Settings(OneLogin_Saml2_Settings):

    def __init__(self, *args, **kwds):
        super(Saml2_Settings, self).__init__(*args, **kwds)

    def get_sp_metadata(self):
        """
        Gets the SP metadata. The XML representation.
        :returns: SP metadata (xml)
        :rtype: string
        """
        metadata = MetaDataBuilder(
            self._OneLogin_Saml2_Settings__sp,
            self._OneLogin_Saml2_Settings__security['authnRequestsSigned'],
            self._OneLogin_Saml2_Settings__security['wantAssertionsSigned'],
            self._OneLogin_Saml2_Settings__security['metadataValidUntil'],
            self._OneLogin_Saml2_Settings__security['metadataCacheDuration'],
            self.get_contacts(), self.get_organization()
        )

        ##### SP SPid patch
        ## mapping xml tag
        tagMapping = {"md0:AssertionConsumerService": 'assertionConsumerService',
                    "md0:AttributeConsumingService": 'attributeConsumingService',
                    "md0:ServiceName":'serviceName', "md0:ServiceDescription":'serviceDescription',
                    "md0:RequestedAttribute":'requestedAttributes', "md1:AttributeValue": 'attributeValue'}

        ## edit meta data
        ns = {'md0': OneLogin_Saml2_Constants.NS_MD, 'md1': OneLogin_Saml2_Constants.NS_SAML}
        xml.etree.ElementTree.register_namespace('md0', OneLogin_Saml2_Constants.NS_MD)
        xml.etree.ElementTree.register_namespace('md1', OneLogin_Saml2_Constants.NS_SAML)

        parsedMetadata = xml.etree.ElementTree.fromstring(metadata)
        SPSSODescriptor = parsedMetadata.find('md0:SPSSODescriptor', ns)

        if not self._OneLogin_Saml2_Settings__security['putMetadataCacheDuration']:
            parsedMetadata.attrib.pop('cacheDuration')

        if not self._OneLogin_Saml2_Settings__security['putMetadataValidUntil']:
            parsedMetadata.attrib.pop('validUntil')

        ## fix AssertionConsumerService index 0
        assertionConsumerService = SPSSODescriptor.find('md0:AssertionConsumerService', ns)
        assertionConsumerService.attrib['index'] = '0'
        assertionConsumerService.set('isDefault', 'true')

        ## fix AttributeConsumingService index 0
        attributeConsumingService = SPSSODescriptor.find('md0:AttributeConsumingService', ns)
        attributeConsumingService.attrib['index'] = '0'
        attributeConsumingService.find('md0:ServiceName', ns).attrib['{http://www.w3.org/XML/1998/namespace}lang'] = self._OneLogin_Saml2_Settings__sp['lang']
        attributeConsumingService.find('md0:ServiceDescription', ns).attrib['{http://www.w3.org/XML/1998/namespace}lang'] = self._OneLogin_Saml2_Settings__sp['lang']

        ## add other AssertionConsumerService
        try:
            for index, value1 in enumerate(self._OneLogin_Saml2_Settings__sp['otherAssertionConsumerService']):

                #indexValue = str(index+1)
                tag = "md0:AssertionConsumerService"
                element = xml.etree.ElementTree.Element(tag,
                    attrib={'Location':value1[tagMapping[tag]]['url'],
                            'Binding':value1[tagMapping[tag]]['binding'],
                            'index': value1[tagMapping[tag]]['index']})

                SPSSODescriptor.insert(index+3,element)

                tag1 = "md0:AttributeConsumingService"
                element1 = xml.etree.ElementTree.Element(tag1, attrib={'index': value1[tagMapping[tag]]['index']})
                SPSSODescriptor.append(element1)

                tag2 = "md0:ServiceName"
                element2 = xml.etree.ElementTree.Element(tag2, attrib={'xml:lang': self._OneLogin_Saml2_Settings__sp['lang']})
                element2.text = value1[tagMapping[tag]][tagMapping[tag1]][tagMapping[tag2]]
                element1.append(element2)

                tag2 = "md0:ServiceDescription"
                element2 = xml.etree.ElementTree.Element(tag2, attrib={'xml:lang': self._OneLogin_Saml2_Settings__sp['lang']})
                element2.text = value1[tagMapping[tag]][tagMapping[tag1]][tagMapping[tag2]]
                element1.append(element2)

                tag3 = "md0:RequestedAttribute"
                for index2, value2 in enumerate(value1[tagMapping[tag]][tagMapping[tag1]][tagMapping[tag3]]):
                    if value2['isRequired']:
                        attrRequired = "true"
                    else:
                         attrRequired = "false"
                    attributi = {'Name': value2['name'], 'FriendlyName': value2['friendlyName'],
                                 'isRequired': attrRequired}
                    element3 = xml.etree.ElementTree.Element(tag3, attrib=attributi)
                    element1.append(element3)

                    for index3, value3 in enumerate(value1[tagMapping[tag]][tagMapping[tag1]][tagMapping[tag3]][index2]['attributeValue']):
                        xml.etree.ElementTree.Element(tag3, attrib=attributi)
                        tag4 = "md1:AttributeValue"
                        element4 = xml.etree.ElementTree.Element(tag4)
                        element4.text = value3
                        element3.append(element4)
        except:
            pass

        ## add other singleLogoutService
        try:
            for index, value1 in enumerate(self._OneLogin_Saml2_Settings__sp['othersSingleLogoutService']):

                #indexValue = str(index+1)
                tag = "md0:SingleLogoutService"
                element = xml.etree.ElementTree.Element(tag,
                    attrib={'Location':value1['url'],
                            'Binding':value1['binding']})

                SPSSODescriptor.insert(index+1,element)
        except:
            pass

        metadata = xml.etree.ElementTree.tostring(parsedMetadata, encoding="unicode")
        ####
        add_encryption = self._OneLogin_Saml2_Settings__security['wantNameIdEncrypted'] or self._OneLogin_Saml2_Settings__security['wantAssertionsEncrypted']

        cert_new = self.get_sp_cert_new()
        metadata = OneLogin_Saml2_Metadata.add_x509_key_descriptors(metadata, cert_new, add_encryption)

        cert = self.get_sp_cert()
        metadata = OneLogin_Saml2_Metadata.add_x509_key_descriptors(metadata, cert, add_encryption)

        # Sign metadata
        if 'signMetadata' in self._OneLogin_Saml2_Settings__security and self._OneLogin_Saml2_Settings__security['signMetadata'] is not False:
            if self._OneLogin_Saml2_Settings__security['signMetadata'] is True:
                # Use the SP's normal key to sign the metadata:
                if not cert:
                    raise OneLogin_Saml2_Error(
                        'Cannot sign metadata: missing SP public key certificate.',
                        OneLogin_Saml2_Error.PUBLIC_CERT_FILE_NOT_FOUND
                    )
                cert_metadata = cert
                key_metadata = self.get_sp_key()
                if not key_metadata:
                    raise OneLogin_Saml2_Error(
                        'Cannot sign metadata: missing SP private key.',
                        OneLogin_Saml2_Error.PRIVATE_KEY_FILE_NOT_FOUND
                    )
            else:
                # Use a custom key to sign the metadata:
                if ('keyFileName' not in self._OneLogin_Saml2_Settings__security['signMetadata'] or
                        'certFileName' not in self._OneLogin_Saml2_Settings__security['signMetadata']):
                    raise OneLogin_Saml2_Error(
                        'Invalid Setting: signMetadata value of the sp is not valid',
                        OneLogin_Saml2_Error.SETTINGS_INVALID_SYNTAX
                    )
                key_file_name = self._OneLogin_Saml2_Settings__security['signMetadata']['keyFileName']
                cert_file_name = self._OneLogin_Saml2_Settings__security['signMetadata']['certFileName']
                key_metadata_file = self._OneLogin_Saml2_Settings__paths['cert'] + key_file_name
                cert_metadata_file = self._OneLogin_Saml2_Settings__paths['cert'] + cert_file_name

                try:
                    with open(key_metadata_file, 'rb') as f_metadata_key:
                        key_metadata = f_metadata_key.read().decode("utf-8")
                except IOError:
                    raise OneLogin_Saml2_Error(
                        'Private key file not readable: %s',
                        OneLogin_Saml2_Error.PRIVATE_KEY_FILE_NOT_FOUND,
                        key_metadata_file
                    )

                try:
                    with open(cert_metadata_file, 'rb') as f_metadata_cert:
                        cert_metadata = f_metadata_cert.read().decode("utf-8")
                except IOError:
                    raise OneLogin_Saml2_Error(
                        'Public cert file not readable: %s',
                        OneLogin_Saml2_Error.PUBLIC_CERT_FILE_NOT_FOUND,
                        cert_metadata_file
                    )

            signature_algorithm = self._OneLogin_Saml2_Settings__security['signatureAlgorithm']
            digest_algorithm = self._OneLogin_Saml2_Settings__security['digestAlgorithm']

            #metadata = OneLogin_Saml2_Metadata.sign_metadata(metadata, key_metadata, cert_metadata, signature_algorithm, digest_algorithm)
            metadata = AddSign(metadata, key_metadata, cert_metadata, False, signature_algorithm, digest_algorithm)

        return metadata

    def validate_metadata(self, xml, fingerprint=None, fingerprintalg='sha1', validatecert=False):
        """
        Validates an XML SP Metadata.

        :param xml: Metadata's XML that will be validate
        :type xml: string

        :param fingerprint: The fingerprint of the public cert
        :type: string

        :param fingerprintalg: The algorithm used to build the fingerprint
        :type: string

        :param validatecert: If true, will verify the signature and if the cert is valid.
        :type: bool

        :returns: a dictionary with the list of found validation errors and signature check
        :rtype: dict
        """
        result = {'schemaValidate':True, 'signCheck':False, 'error':0, 'msg':''}

        assert isinstance(xml, compat.text_types)

        if len(xml) == 0:
            raise Exception('Empty string supplied as input')

        #errors = {'validate':[], 'signCheck':0}
        root = OneLogin_Saml2_XML.validate_xml(xml, 'saml-schema-metadata-2.0.xsd', self._OneLogin_Saml2_Settings__debug)
        if isinstance(root, str):
            result['msg'] = root
            result['schemaValidate'] = False
        else:
            if root.tag != '{%s}EntityDescriptor' % OneLogin_Saml2_Constants.NS_MD:
                result['msg'] = 'noEntityDescriptor_xml'
                result['error'] = 1
                result['schemaValidate'] = False
                #errors.append('noEntityDescriptor_xml')
            else:
                if (len(root.findall('.//md:SPSSODescriptor', namespaces=OneLogin_Saml2_Constants.NSMAP))) != 1:
                    #errors.append('onlySPSSODescriptor_allowed_xml')
                    result['msg'] = 'onlySPSSODescriptor_allowed_xml'
                    result['error'] = 2
                    result['schemaValidate'] = False
                else:
                    valid_until, cache_duration = root.get('validUntil'), root.get('cacheDuration')

                    if valid_until:
                        valid_until = Saml2_Utils.parse_SAML_to_time(valid_until)
                    expire_time = Saml2_Utils.get_expire_time(cache_duration, valid_until)
                    if expire_time is not None and int(time()) > int(expire_time):
                        #errors.append('expired_xml')
                        result['msg'] = 'expired_xml'
                        result['error'] = 3
                        result['schemaValidate'] = False

        # Validate Sign
        signCheck = Saml2_Utils.validate_metadata_sign(xml, fingerprint=fingerprint,
                        fingerprintalg=fingerprintalg, validatecert=validatecert)
        if signCheck:
            result['signCheck'] = True

        return result

class Saml2_Utils(OneLogin_Saml2_Utils):
    def __init__(self, *args, **kwds):
        super(OneLogin_Saml2_Utils, self).__init__(*args, **kwds)

    @staticmethod
    @return_false_on_exception
    def validate_node_sign(signature_node, elem, cert=None, fingerprint=None, fingerprintalg='sha1', validatecert=False, debug=False):
        """
        Validates a signature node.

        :param signature_node: The signature node
        :type: Node

        :param xml: The element we should validate
        :type: Document

        :param cert: The public cert
        :type: string

        :param fingerprint: The fingerprint of the public cert
        :type: string

        :param fingerprintalg: The algorithm used to build the fingerprint
        :type: string

        :param validatecert: If true, will verify the signature and if the cert is valid.
        :type: bool

        :param debug: Activate the xmlsec debug
        :type: bool

        :param raise_exceptions: Whether to return false on failure or raise an exception
        :type raise_exceptions: Boolean
        """
        if (cert is None or cert == '') and fingerprint:
            x509_certificate_nodes = OneLogin_Saml2_XML.query(signature_node, '//ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate')
            if len(x509_certificate_nodes) > 0:
                x509_certificate_node = x509_certificate_nodes[0]
                x509_cert_value = OneLogin_Saml2_XML.element_text(x509_certificate_node)
                x509_cert_value_formatted = Saml2_Utils.format_cert(x509_cert_value)
                x509_fingerprint_value = Saml2_Utils.calculate_x509_fingerprint(x509_cert_value_formatted, fingerprintalg)
                if fingerprint == x509_fingerprint_value:
                    cert = x509_cert_value_formatted

        if cert is None or cert == '':
            raise OneLogin_Saml2_Error(
                'Could not validate node signature: No certificate provided.',
                OneLogin_Saml2_Error.CERT_NOT_FOUND
            )

        # Check if Reference URI is empty
        #reference_elem = OneLogin_Saml2_XML.query(signature_node, '//ds:Reference')
        #if len(reference_elem) > 0:
        #    if reference_elem[0].get('URI') == '':
        #        reference_elem[0].set('URI', '#%s' % signature_node.getparent().get('ID'))

        if validatecert:
            manager = xmlsec.KeysManager()
            manager.load_cert_from_memory(cert, xmlsec.KeyFormat.CERT_PEM, xmlsec.KeyDataType.TRUSTED)
            dsig_ctx = xmlsec.SignatureContext(manager)
        else:
            dsig_ctx = xmlsec.SignatureContext()
            dsig_ctx.key = xmlsec.Key.from_memory(cert, xmlsec.KeyFormat.CERT_PEM, None)

        dsig_ctx.set_enabled_key_data([xmlsec.KeyData.X509])

        try:
            dsig_ctx.verify(signature_node)
        except Exception as err:
            raise OneLogin_Saml2_ValidationError(
                'Signature validation failed. SAML Response rejected. %s',
                OneLogin_Saml2_ValidationError.INVALID_SIGNATURE,
                str(err)
            )

        return True

    @staticmethod
    @return_false_on_exception
    def validate_metadata_sign(xml, cert=None, fingerprint=None, fingerprintalg='sha1', validatecert=False, debug=False):
        """
        Validates a signature of a EntityDescriptor.

        :param xml: The element we should validate
        :type: string | Document

        :param cert: The public cert
        :type: string

        :param fingerprint: The fingerprint of the public cert
        :type: string

        :param fingerprintalg: The algorithm used to build the fingerprint
        :type: string

        :param validatecert: If true, will verify the signature and if the cert is valid.
        :type: bool

        :param debug: Activate the xmlsec debug
        :type: bool

        :param raise_exceptions: Whether to return false on failure or raise an exception
        :type raise_exceptions: Boolean
        """
        if xml is None or xml == '':
            raise Exception('Empty string supplied as input')

        elem = OneLogin_Saml2_XML.to_etree(xml)
        xmlsec.enable_debug_trace(debug)
        xmlsec.tree.add_ids(elem, ["ID"])

        signature_nodes = OneLogin_Saml2_XML.query(elem, '/md:EntitiesDescriptor/ds:Signature')

        if len(signature_nodes) == 0:
            signature_nodes += OneLogin_Saml2_XML.query(elem, '/md:EntityDescriptor/ds:Signature')

            if len(signature_nodes) == 0:
                signature_nodes += OneLogin_Saml2_XML.query(elem, '/md:EntityDescriptor/md:SPSSODescriptor/ds:Signature')
                signature_nodes += OneLogin_Saml2_XML.query(elem, '/md:EntityDescriptor/md:IDPSSODescriptor/ds:Signature')

        if len(signature_nodes) > 0:
            for signature_node in signature_nodes:
                # Raises expection if invalid
                Saml2_Utils.validate_node_sign(signature_node, elem, cert, fingerprint, fingerprintalg, validatecert, debug, raise_exceptions=True)
            return True
        else:
            raise Exception('Could not validate metadata signature: No signature nodes found.')

def AddSign(xml, key, cert, debug=False, sign_algorithm=OneLogin_Saml2_Constants.RSA_SHA1,
        digest_algorithm=OneLogin_Saml2_Constants.SHA1, addKeyValue = False):
        """
        Adds signature key and senders certificate to an element (Message or
        Assertion).

        :param xml: The element we should sign
        :type: string | Document

        :param key: The private key
        :type: string

        :param cert: The public
        :type: string

        :param debug: Activate the xmlsec debug
        :type: bool

        :param sign_algorithm: Signature algorithm method
        :type sign_algorithm: string

        :param digest_algorithm: Digest algorithm method
        :type digest_algorithm: string

        :returns: Signed XML
        :rtype: string
        """
        if xml is None or xml == '':
            raise Exception('Empty string supplied as input')

        elem = OneLogin_Saml2_XML.to_etree(xml)
        xmlsec.enable_debug_trace(debug)
        xmlsec.tree.add_ids(elem, ["ID"])
        # Sign the metadata with our private key.
        sign_algorithm_transform_map = {
            OneLogin_Saml2_Constants.DSA_SHA1: xmlsec.Transform.DSA_SHA1,
            OneLogin_Saml2_Constants.RSA_SHA1: xmlsec.Transform.RSA_SHA1,
            OneLogin_Saml2_Constants.RSA_SHA256: xmlsec.Transform.RSA_SHA256,
            OneLogin_Saml2_Constants.RSA_SHA384: xmlsec.Transform.RSA_SHA384,
            OneLogin_Saml2_Constants.RSA_SHA512: xmlsec.Transform.RSA_SHA512
        }
        sign_algorithm_transform = sign_algorithm_transform_map.get(sign_algorithm, xmlsec.Transform.RSA_SHA1)

        signature = xmlsec.template.create(elem, xmlsec.Transform.EXCL_C14N, sign_algorithm_transform, ns='ds')

        issuer = OneLogin_Saml2_XML.query(elem, '//saml:Issuer')
        if len(issuer) > 0:
            issuer = issuer[0]
            issuer.addnext(signature)
        else:
            elem.insert(0, signature)

        elem_id = elem.get('ID', None)
        if elem_id:
            elem_id = '#' + elem_id
        #else:
        #    elem_id = ""

        digest_algorithm_transform_map = {
            OneLogin_Saml2_Constants.SHA1: xmlsec.Transform.SHA1,
            OneLogin_Saml2_Constants.SHA256: xmlsec.Transform.SHA256,
            OneLogin_Saml2_Constants.SHA384: xmlsec.Transform.SHA384,
            OneLogin_Saml2_Constants.SHA512: xmlsec.Transform.SHA512
        }
        digest_algorithm_transform = digest_algorithm_transform_map.get(digest_algorithm, xmlsec.Transform.SHA1)

        ref = xmlsec.template.add_reference(signature, digest_algorithm_transform, uri=elem_id)
        xmlsec.template.add_transform(ref, xmlsec.Transform.ENVELOPED)
        xmlsec.template.add_transform(ref, xmlsec.Transform.EXCL_C14N)
        key_info = xmlsec.template.ensure_key_info(signature)
        if addKeyValue:
            xmlsec.template.add_key_value(key_info)
        xmlsec.template.add_x509_data(key_info)

        dsig_ctx = xmlsec.SignatureContext()
        sign_key = xmlsec.Key.from_memory(key, xmlsec.KeyFormat.PEM, None)
        sign_key.load_cert_from_memory(cert, xmlsec.KeyFormat.PEM)

        dsig_ctx.key = sign_key
        dsig_ctx.sign(signature)

        return OneLogin_Saml2_XML.to_string(elem)

def validateAssertion(xml, fingerprint=None, fingerprintalg=None):

    result = {'schemaValidate':False, 'signCheck':False, 'certValidity':False,
              'certAllowed':True, 'error':0, 'msg':'', 'assertionName': None, 'chkTime': None,
              'chkStatus': None, 'serviceAttributes': None}

    assert isinstance(xml, compat.text_types)

    if len(xml) == 0:
        result['error'] = 1
        result['msg'] = 'Empty string supplied as input'
        return  result

    OneLoginResponse = OneLogin_Saml2_Response({}, Saml2_Utils.b64encode(xml))
    xml = xmlRemoveDeclaration(xml)
    parsedassertion = etree.fromstring(xml)

    # assertion name path
    assertionNameXpath = "local-name(/*)"
    assertionName = parsedassertion.xpath(assertionNameXpath)
    assertionName = str(assertionName)

    # find assertion schema
    if assertionName == 'EntityDescriptor':
        asscertionShema  = 'saml-schema-metadata-2.0.xsd'
    elif assertionName == 'Response':
        asscertionShema  = 'saml-schema-protocol-2.0.xsd'
    elif assertionName == 'AuthnRequest':
        asscertionShema  = 'saml-schema-protocol-2.0.xsd'
    else:
        result['error'] = 2
        result['msg'] = 'Assertion unknown'
        return  result

    # siganture node path
    signatureNodeXpath = ".//*[local-name()='Signature']"

    if assertionName == 'Response':
        signatureNodeXpath = "*[local-name(/*)='Response']//*[local-name()='Signature']"

    result['assertionName'] = assertionName
    # get certificate signing
    try:
        signingcert = easyspid.lib.easyspid.get_signature_cert(xml)

    except Exception as error:
        signingcert = False

    # validate xml against its schema
    schemaCheck = OneLogin_Saml2_XML.validate_xml(xml, asscertionShema, False)
    if isinstance(schemaCheck, str):
        result['msg'] = schemaCheck
        result['schemaValidate'] = False
        result['error'] = 3
    else:
        result['schemaValidate'] = True

    # check signature
    if signingcert:
        signingfingerprintalg = 'sha1'
        if fingerprintalg is not None:
            signingfingerprintalg = fingerprintalg

        signingfingerprint = (easyspid.lib.easyspid.calcCertFingerprint(signingcert, signingfingerprintalg))['result']

        if assertionName == 'EntityDescriptor' and fingerprint is None:
            allowedCert = easyspid.lib.easyspid.get_metadata_allowed_cert(xml)
            allowedfingerprint = (easyspid.lib.easyspid.calcCertFingerprint(allowedCert, signingfingerprintalg))['result']

        elif assertionName != 'EntityDescriptor' and fingerprint is None:
            allowedfingerprint = signingfingerprint

        if fingerprint is not None:
            allowedfingerprint = fingerprint

        signCheck = Saml2_Utils.validate_sign(xml, cert=signingcert, fingerprint=signingfingerprint,
            fingerprintalg = signingfingerprintalg, validatecert=False, debug=False, xpath=signatureNodeXpath, multicerts=None)

        if signCheck:
            result['signCheck'] = True
        else:
            result['error'] = 3

        # check expired certificate
        certTimeValdity = easyspid.lib.easyspid.timeValidateCert(signingcert)
        if certTimeValdity:
            result['certValidity'] = True

        # checktime certificate allow
        if allowedfingerprint != signingfingerprint:
            result['certAllowed'] = False
            result['error'] = 3

    elif not signingcert and assertionName == 'AuthnRequest':
        result['signCheck'] = None
        result['certValidity'] = None
        result['certAllowed'] = None

    if assertionName == 'Response':
        try:
            OneLoginResponse.validate_timestamps(raise_exceptions=True)
            result['chkTime'] = True

        except OneLogin_Saml2_ValidationError as error:
            result['chkTime'] = False
            result['error'] = 3

        try:
            OneLoginResponse.check_status()
            result['chkStatus'] = True

        except OneLogin_Saml2_ValidationError as error:
            result['chkStatus'] = False
            result['error'] = 3

    try:
        result['serviceAttributes'] = OneLoginResponse.get_attributes()
    except:
        pass

    return result

def xmlRemoveDeclaration(xml):

    if len(xml) == 0:
        return xml

    return re.sub("<\?xml[^>]+>", "", xml)

def waitFuture(future, timeout=0):
    start = time.time()
    while not future.done():

        if timeout > 0 and (time.time()-start) > timeout:
            future.cancel()
            raise asyncio.CancelledError

    return future.result()

async def getResponseError(xmlTreeRespponse, sp = None, namespace = None, errorsKey = 'SAML'):

    result = {'error':'0', 'status': None, 'service': None}

    statusCode = xmlTreeRespponse.find('md0:Status/md0:StatusCode', namespace).attrib['Value'].strip()
    subStatusCode = xmlTreeRespponse.find('md0:Status/md0:StatusCode/md0:StatusCode', namespace).attrib['Value'].strip()
    statusMessage = xmlTreeRespponse.find('md0:Status/md0:StatusMessage', namespace).text.strip()

    #laod SAML errors
    try:
        with open(os.path.join(globalsObj.modules_basedir, globalsObj.easyspid_saml_errors), 'rb') as myfile:
            saml_errors = jsonpickle.decode(myfile.read().decode("utf-8"))
    except:
        with open(globalsObj.easyspid_saml_errors, 'rb') as myfile:
            saml_errors = jsonpickle.decode(myfile.read().decode("utf-8"))

    if sp is not None:
        spSettings = await globalsObj.DbConnections['samlDb'].execute_statment("get_sp_settings('%s')" % sp)

        if spSettings['error'] == 0 and spSettings['result'] != None:
            if 'singleErrorService' in spSettings['result'][0]['settings']['sp']:
                service = spSettings['result'][0]['settings']['sp']['singleErrorService']['url']
                result['service'] = service


            error = next((item for item in saml_errors[errorsKey] if item['statusMessage'] == statusMessage), False)
            if not error:
                userMessage = statusCode + ", " + subStatusCode + ", " + statusMessage
                result['status'] = {'statusCode':statusCode, 'subStatusCode':subStatusCode,
                    'statusMessage': statusMessage, "ITMessage": userMessage, "ENMessage": userMessage}
            else:
                result['status'] = error

            return result

        elif spSettings['error'] == 0 and spSettings['result'] == None:
            result['error'] = 'easyspid114'
            return result

        elif spSettings['error'] > 0:
            result['error'] = spSettings['error']
            return result

    else:
        service = globalsObj.easyspid_default_url
        result['status'] = {'statusCode':statusCode, 'subStatusCode':subStatusCode, 'statusMessage': statusMessage}
        result['service'] = service
        return result

class goExit(Exception):
    def __init__(self, expression, message):
        self.expression = expression
        self.message = message