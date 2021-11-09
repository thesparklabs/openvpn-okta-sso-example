import sys, os
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

    def GetUser(self, state):
        if state in self.storage:
            return self.storage[state]
        return None 

    def AllowUser(self, state):
        if not state in self.storage:
            return False
        userStorage = self.storage[state]
        self.clientAllow(userStorage["cid"], userStorage["kid"])
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
                    print(line)
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
        print("m:%s" % line)
        split = line.split(':', 1)
        if len(split) != 2:
            return #Ignore
        command = split[0]
        content = split[1]

        if command == ">CLIENT":
            parts = content.split(',', 1)
            if len(parts) != 2:
                return
            if parts[0] == "CONNECT":
                self.clientData = {}
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
                    # Set pending auth
                    # client-pending-auth {CID} {EXTRA} {TIMEOUT}

                    # Generate a state and nonce
                    state = str(uuid.uuid4())
                    nonce = str(uuid.uuid4())

                    self.storage[state] = {
                        "nonce": nonce,
                        "cid": self.clientID,
                        "kid": self.clientKID
                    }

                    loginurl = "%s?state=%s" % (self.loginUrl, state)
                    reply = "client-pending-auth %s OPEN_URL:%s\n" % (self.clientID, loginurl)
                    self.conn.write(reply.encode())
                    print("Wrote %s" % reply)
                    #Clear
                    self.clientID = None
                    self.clientKID = None
                    self.clientData = {}
                    return

                env = parts[1].split('=', 1)
                if len(env) != 2:
                    return
                self.clientData[env[0]] = env[1]

    def clientDeny(self, cid, kid, reason, clientReason=None):
        reply = "client-deny %s %s \"%s\"" % (cid, kid, reason)
        if clientReason != None:
            reply += " \"%s\"" % clientReason
        reply += "\n"
        self.conn.write(reply.encode())

    def clientAllow(self, cid, kid):
        reply = "client-auth-nt %s %s\n" % (cid, kid)
        self.conn.write(reply.encode())