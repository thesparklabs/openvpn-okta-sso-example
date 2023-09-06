import sys, os, base64
import telnetlib
import uuid, threading

from flask_login.utils import _user_context_processor

class OpenVPNSSOManager:
    def __init__(self, port, baseloginUrl):
        self.port = port
        self.loginUrl = baseloginUrl
        self.conn = telnetlib.Telnet()
        self.storage = {}
        self.started = False
        self.sessions = {}
        self.clientID = None
        self.clientType = None

    def GetUser(self, state):
        if state in self.storage:
            return self.storage[state]
        return None 

    def AllowUser(self, state, username):
        if not state in self.storage:
            return False
        userStorage = self.storage[state]
        base64User = base64.b64encode(username.encode('utf-8')).decode('utf-8')
        self.clientAllow(userStorage["cid"], userStorage["kid"], base64User)
        del self.storage[state]
        return True

    def Start(self):
        if self.started:
            return
        self.started = True
        print("Starting thread")
        self.t = threading.Thread(target=self.Connect, daemon=True)
        self.t.start()

    def Connect(self):
        try:
            self.conn.open('127.0.0.1', self.port)
            print("OpenVPN Connected")

            while True:
                try:
                    line = self.conn.read_until(b"\n")
                    line = str(line.decode())
                except Exception as e:
                    print(e)
                    break

                line = line.replace("\n", "").replace("\r", "").strip()
                if line == "":
                    pass
                
                self.processCommand(line)

            print("Management Disconnected")         

        except Exception as e:
            print("Connection to OpenVPN failed.")
            print(e)

        self.conn.close()

    def processCommand(self, line):
        split = line.split(':', 1)
        if len(split) != 2:
            return #Ignore
        command = split[0]
        content = split[1]

        if command == ">CLIENT":
            parts = content.split(',', 1)
            if len(parts) != 2:
                return
            if parts[0] in ["CONNECT", "ESTABLISHED", "REAUTH", "DISCONNECT"]:
                self.clientData = {}
                self.clientType = parts[0]
                cids = parts[1].split(',')
                self.clientID = cids[0]
                if len(cids) > 1:
                    self.clientKID = cids[1]
                else:
                    self.clientKID = None

            elif parts[0] == "ENV":
                #Make sure we got a CONNECT
                if self.clientID == None:
                    return
                if parts[1] == "END":
                    if self.clientType == "CONNECT":
                        self.clientConnect(self.clientID, self.clientKID)
                        #Clear session data if any
                        if self.clientID in self.sessions:
                            del self.sessions[self.clientID]
                    elif self.clientType == "ESTABLISHED":
                        self.sessions[self.clientID] = {}
                        if "session_id" in self.clientData:
                            self.sessions[self.clientID]["SessionID"] = self.clientData["session_id"]
                    elif self.clientType == "REAUTH":
                        self.clientReauth(self.clientID, self.clientKID)
                    elif self.clientType == "DISCONNECT":
                        if self.clientID in self.sessions:
                            del self.sessions[self.clientID]
                    
                    #Clear
                    self.clientID = None
                    self.clientKID = None
                    self.clientData = {}
                    return

                env = parts[1].split('=', 1)
                if len(env) != 2:
                    return
                self.clientData[env[0]] = env[1]

    def clientReauth(self, cid, kid):
        if not cid in self.sessions or not "SessionID" in self.sessions[cid] or not "session_id" in self.clientData:
            return
        if self.sessions[cid]["SessionID"] != self.clientData["session_id"]:
            return
        # OpenVPN does not allow auth-gen-token without a username by default, so we allow it here
        if self.clientData["session_state"] in ["Authenticated", "AuthenticatedEmptyUser"]:
            reply = "client-auth-nt %s %s\n" % (cid, kid)
            self.conn.write(reply.encode())
        return
    
    def clientConnect(self, cid, kid):
        # Set pending auth
        # client-pending-auth {CID} {EXTRA} {TIMEOUT}

        # Generate a state and nonce
        state = str(uuid.uuid4())
        nonce = str(uuid.uuid4())

        self.storage[state] = {
            "nonce": nonce,
            "cid": cid,
            "kid": kid
        }

        loginurl = "%s?state=%s" % (self.loginUrl, state)
        reply = "client-pending-auth %s OPEN_URL:%s\n" % (cid, loginurl)
        self.conn.write(reply.encode())

    def clientDeny(self, cid, kid, reason, clientReason=None):
        reply = "client-deny %s %s \"%s\"" % (cid, kid, reason)
        if clientReason != None:
            reply += " \"%s\"" % clientReason
        reply += "\n"
        self.conn.write(reply.encode())

    def clientAllow(self, cid, kid, b64User):
        reply = 'client-auth %s %s\npush "auth-token-user %s"\nEND\n' % (cid, kid, b64User)
        self.conn.write(reply.encode())