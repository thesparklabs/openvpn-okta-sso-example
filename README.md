# Viscosity + Flask + Okta Single Sign On Example
This example is designed to demonstrate Single Sign On support with Viscosity from a basic Flask and OpenVPN Management server using Okta for client/user management and login.

This example is not designed to be used stand-alone in a production environment, it is designed as an example to help guide integration with an existing login or client/user management system.

# Flask + Okta Hosted Login Example
This example is based on the Flask + Okta Hosted Login example available at https://github.com/okta/samples-python-flask/tree/master/okta-hosted-login

## Prerequisites

Before running this sample, you will need the following:

* An Okta Developer Account, you can sign up for one at https://developer.okta.com/signup/.
* An Okta Application, configured for Web mode. This is done from the Okta Developer Console and you can find instructions [here][OIDC WEB Setup Instructions].  When following the wizard, use the default properties.  They are are designed to work with our sample applications.
* A running OpenVPN 2.5 server with the following commands:
```management 127.0.0.1 50123 
auth-user-pass-optional
management-client-auth
```

## Running This Example

To run this application, you first need to clone this repo:

```bash
git clone https://github.com/thesparklabs/openvpn-two-factor-extensions.git
cd samples-python-flask
```

Then install dependencies:

```bash
pip install -r requirements.txt
```

Viscosity clients usually do not need modification, "Use Username/Password authentication" just needs to be disabled.

You also need to gather the following information from the Okta Developer Console:

- **Client ID** and **Client Secret** - These can be found on the "General" tab of the Web application that you created earlier in the Okta Developer Console.
- **Issuer** - This is the URL of the authorization server that will perform authentication.  All Developer Accounts have a "default" authorization server.  The issuer is a combination of your Org URL (found in the upper right of the console home page) and `/oauth2/default`. For example, `https://dev-1234.oktapreview.com/oauth2/default`.

Now that you have the information needed from your organization, open the `okta-hosted-login` directory. Copy the [`client_secrets.json.dist`](client_secrets.json.dist) to `client_secrets.json` and fill in the information you gathered.

Now start the app server:

```
python main.py
```

Now navigate to http://{{YOUR_DOMAIN}} in your browser.

If you see a home page that prompts you to login, then things are working!  Clicking the **Log in** button will redirect you to the Okta hosted sign-in page.

You can login with the same account that you created when signing up for your Developer Org, or you can use a known username and password from your Okta Directory.

**Note:** If you are currently using your Developer Console, you already have a Single Sign-On (SSO) session for your Org.  You will be automatically logged into your application as the same user that is using the Developer Console.  You may want to use an incognito tab to test the flow from a blank slate.

[OIDC Web Setup Instructions]: https://developer.okta.com/authentication-guide/implementing-authentication/auth-code#1-setting-up-your-application

Once the above test is working, you can then connect with Viscosity to your OpenVPN server, and you should see an Okta hosted web prompt to login.
