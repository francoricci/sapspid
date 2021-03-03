from response import ResponseObj, RequestHandler, StaticFileHandler
from onelogin.saml2.utils import OneLogin_Saml2_Utils
import jsonpickle
import sys
import os
from tornado import iostream


class StaticFileHandler(StaticFileHandler):

    async def post(self, file):
        try:
            # get response and Relay state
            responsePost = self.get_argument('JSONResponse')
            srelayPost = self.get_argument('RelayState')

            try:
                JSONResponse = OneLogin_Saml2_Utils.b64decode(responsePost)
            except Exception:
                try:
                    JSONResponse = OneLogin_Saml2_Utils.decode_base64_and_inflate(responsePost)
                except Exception:
                    pass

            responsedict = jsonpickle.decode(JSONResponse)
            samlErrors = responsedict['result']['samlErrors']

            content = self.get_content(os.path.join(self.root, file))
            tmp = b""

            if isinstance(content, bytes):
                content = [content]

            for chunk in content:
                try:
                    tmp = tmp.join([chunk])

                except iostream.StreamClosedError:
                    return

            content = tmp
            content = content.replace(b"$http_error$", bytes(str(responsedict['error']['httpcode']),'utf-8'))
            content = content.replace(b"$ITMessage$", bytes(samlErrors['ITMessage'], 'utf-8' ))
            content = content.replace(b"$ENMessage$", bytes(samlErrors['ENMessage'], 'utf-8'))
            content = content.replace(b"$statusCode$", bytes(samlErrors['statusCode'], 'utf-8'))
            content = content.replace(b"$subStatusCode$", bytes(samlErrors['subStatusCode'], 'utf-8'))
            content = content.replace(b"$statusMessage$", bytes(samlErrors['statusMessage'], 'utf-8'))

            await self.get(file, False)

            self.set_header("Content-Length", len(content))
            self.write(content)
            await self.flush()

        except AssertionError as inst:

            self.set_header("Content-Length", len(content))
            self.write(content)
            await self.flush()