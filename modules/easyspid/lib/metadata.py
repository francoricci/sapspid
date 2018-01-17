from time import gmtime, strftime, time
from datetime import datetime

from onelogin.saml2 import compat
from onelogin.saml2.metadata import OneLogin_Saml2_Metadata
from xml.sax.saxutils import quoteattr
from xml.sax.saxutils import escape

try:
    basestring
except NameError:
    basestring = str


def MetaDataBuilder(sp, authnsign=False, wsign=False, valid_until=None, cache_duration=None, contacts=None, organization=None):
    """
    Builds the metadata of the SP

    :param sp: The SP data
    :type sp: string

    :param authnsign: authnRequestsSigned attribute
    :type authnsign: string

    :param wsign: wantAssertionsSigned attribute
    :type wsign: string

    :param valid_until: Metadata's expiry date
    :type valid_until: string|DateTime|Timestamp

    :param cache_duration: Duration of the cache in seconds
    :type cache_duration: int|string

    :param contacts: Contacts info
    :type contacts: dict

    :param organization: Organization info
    :type organization: dict
    """
    if valid_until is None:
        valid_until = int(time()) + OneLogin_Saml2_Metadata.TIME_VALID
    if not isinstance(valid_until, basestring):
        if isinstance(valid_until, datetime):
            valid_until_time = valid_until.timetuple()
        else:
            valid_until_time = gmtime(valid_until)
        valid_until_str = strftime(r'%Y-%m-%dT%H:%M:%SZ', valid_until_time)
    else:
        valid_until_str = valid_until

    if cache_duration is None:
        cache_duration = OneLogin_Saml2_Metadata.TIME_CACHED
    if not isinstance(cache_duration, compat.str_type):
        cache_duration_str = 'PT%sS' % cache_duration  # Period of Time x Seconds
    else:
        cache_duration_str = cache_duration

    if contacts is None:
        contacts = {}
    if organization is None:
        organization = {}

    sls = ''
    if 'singleLogoutService' in sp and 'url' in sp['singleLogoutService']:
        sls = MD_SLS % \
            {
                'binding': quoteattr(sp['singleLogoutService']['binding']),
                'location': quoteattr(sp['singleLogoutService']['url'])
            }

    str_authnsign = 'true' if authnsign else 'false'
    str_wsign = 'true' if wsign else 'false'

    str_organization = ''
    if len(organization) > 0:
        organization_names = []
        organization_displaynames = []
        organization_urls = []
        for (lang, info) in organization.items():
            organization_names.append("""        <md:OrganizationName xml:lang="%s">%s</md:OrganizationName>""" % (lang, escape(info['name'])))
            organization_displaynames.append("""        <md:OrganizationDisplayName xml:lang="%s">%s</md:OrganizationDisplayName>""" % (lang, escape(info['displayname'])))
            organization_urls.append("""        <md:OrganizationURL xml:lang="%s">%s</md:OrganizationURL>""" % (lang, escape(info['url'])))
        org_data = '\n'.join(organization_names) + '\n' + '\n'.join(organization_displaynames) + '\n' + '\n'.join(organization_urls)
        str_organization = """    <md:Organization>\n%(org)s\n    </md:Organization>""" % {'org': org_data}

    str_contacts = ''
    if len(contacts) > 0:
        contacts_info = []
        for (ctype, info) in contacts.items():
            contact = MD_CONTACT_PERSON % \
                {
                    'type': quoteattr(ctype),
                    'name': escape(info['givenName']),
                    'email': escape(info['emailAddress']),
                }
            contacts_info.append(contact)
        str_contacts = '\n'.join(contacts_info)

    str_attribute_consuming_service = ''
    if 'attributeConsumingService' in sp and len(sp['attributeConsumingService']):
        attr_cs_desc_str = ''
        if "serviceDescription" in sp['attributeConsumingService']:
            attr_cs_desc_str = """            <md:ServiceDescription xml:lang="it">%s</md:ServiceDescription>
""" % escape(sp['attributeConsumingService']['serviceDescription'])

        requested_attribute_data = []
        for req_attribs in sp['attributeConsumingService']['requestedAttributes']:
            req_attr_nameformat_str = req_attr_friendlyname_str = req_attr_isrequired_str = ''
            req_attr_aux_str = ' />'

            if 'nameFormat' in req_attribs.keys() and req_attribs['nameFormat']:
                req_attr_nameformat_str = " NameFormat=%s" % quoteattr(req_attribs['nameFormat'])
            if 'friendlyName' in req_attribs.keys() and req_attribs['friendlyName']:
                req_attr_nameformat_str = " FriendlyName=%s" % quoteattr(req_attribs['friendlyName'])
            if 'isRequired' in req_attribs.keys() and req_attribs['isRequired']:
                req_attr_isrequired_str = " isRequired=%s" % quoteattr('true') if req_attribs['isRequired'] else quoteattr('false')
            if 'attributeValue' in req_attribs.keys() and req_attribs['attributeValue']:
                if isinstance(req_attribs['attributeValue'], basestring):
                    req_attribs['attributeValue'] = [req_attribs['attributeValue']]

                req_attr_aux_str = ">"
                for attrValue in req_attribs['attributeValue']:
                    req_attr_aux_str += """
            <saml:AttributeValue xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">%(attributeValue)s</saml:AttributeValue>""" % \
                        {
                            'attributeValue': escape(attrValue)
                        }
                req_attr_aux_str += """
        </md:RequestedAttribute>"""

            requested_attribute = """            <md:RequestedAttribute Name=%(req_attr_name)s%(req_attr_nameformat_str)s%(req_attr_friendlyname_str)s%(req_attr_isrequired_str)s%(req_attr_aux_str)s""" % \
                {
                    'req_attr_name':  quoteattr(req_attribs['name']),
                    'req_attr_nameformat_str': req_attr_nameformat_str,
                    'req_attr_friendlyname_str': req_attr_friendlyname_str,
                    'req_attr_isrequired_str': req_attr_isrequired_str,
                    'req_attr_aux_str': req_attr_aux_str
                }

            requested_attribute_data.append(requested_attribute)

        str_attribute_consuming_service = """        <md:AttributeConsumingService index="1">
        <md:ServiceName xml:lang="it">%(service_name)s</md:ServiceName>
%(attr_cs_desc)s%(requested_attribute_str)s
    </md:AttributeConsumingService>
""" % \
            {
                'service_name': escape(sp['attributeConsumingService']['serviceName']),
                'attr_cs_desc': attr_cs_desc_str,
                'requested_attribute_str': '\n'.join(requested_attribute_data)
            }

    metadata = MD_ENTITY_DESCRIPTOR % \
        {
            'valid': ('validUntil=%s' % quoteattr(valid_until_str)) if valid_until_str else quoteattr(''),
            'cache': ('cacheDuration=%s' % quoteattr(cache_duration_str)) if cache_duration_str else quoteattr(''),
            'entity_id':  quoteattr(sp['entityId']),
            'authnsign': quoteattr(str_authnsign),
            'wsign': quoteattr(str_wsign),
            'name_id_format': escape(sp['NameIDFormat']),
            'binding': quoteattr(sp['assertionConsumerService']['binding']),
            'location': quoteattr(sp['assertionConsumerService']['url']),
            'sls': sls,
            'organization': str_organization,
            'contacts': str_contacts,
            'attribute_consuming_service': str_attribute_consuming_service
        }

    return metadata


## Metadata Templates ##

MD_ENTITY_DESCRIPTOR = """\
<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     %(valid)s
                     %(cache)s
                     entityID=%(entity_id)s>
    <md:SPSSODescriptor AuthnRequestsSigned=%(authnsign)s WantAssertionsSigned=%(wsign)s protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
%(sls)s        <md:NameIDFormat>%(name_id_format)s</md:NameIDFormat>
        <md:AssertionConsumerService Binding=%(binding)s
                                     Location=%(location)s
                                     index="1" />
%(attribute_consuming_service)s    </md:SPSSODescriptor>
%(organization)s
%(contacts)s
</md:EntityDescriptor>"""

MD_SLS = """\
        <md:SingleLogoutService Binding=%(binding)s
                                Location=%(location)s />\n"""

MD_CONTACT_PERSON = """\
    <md:ContactPerson contactType=%(type)s>
        <md:GivenName>%(name)s</md:GivenName>
        <md:EmailAddress>%(email)s</md:EmailAddress>
    </md:ContactPerson>"""