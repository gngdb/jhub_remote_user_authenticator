import os

from jupyterhub.handlers import BaseHandler

from jupyterhub.auth import Authenticator

from jupyterhub.auth import LocalAuthenticator

from jupyterhub.utils import url_path_join

from tornado import gen, web

from traitlets import Unicode





class RemoteUserLoginHandler(BaseHandler):



    @gen.coroutine

    def get(self):


        header_name = self.authenticator.header_name

        remote_user = self.request.headers.get(header_name, "")

        data = {'username': remote_user }

        username = yield self.authenticator.authenticate(self,data)

        if username:

            user = self.user_from_username(username)

            self.set_login_cookie(user)

            self.redirect(url_path_join(self.hub.server.base_url, 'home'))

        else:


            raise web.HTTPError(403)





class RemoteUserAuthenticator(LocalAuthenticator):

    """

    Accept the authenticated user name from the REMOTE_USER HTTP header.

    """

    header_name = Unicode(

        default_value='REMOTE_USER',

        config=True,

        help="""HTTP header to inspect for the authenticated username.""")



    def get_handlers(self, app):

        return [

            (r'/login', RemoteUserLoginHandler),

        ]



    @gen.coroutine

    def authenticate(self, handler, data):

        username = data['username']

        nameduser = handler.user_from_username(username)

        self.add_user(nameduser)

        # if we have a user initialisation script, run it now
        if hasattr(self, 'postadduser_script'):
            import subprocess
            subprocess.call([self.postadduser_script, nameduser])

        return username





