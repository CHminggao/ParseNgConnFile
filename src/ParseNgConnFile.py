'''
Created on May 16, 2013

@author: rainman
'''

import base64
import md5
import os
from Crypto.Cipher import AES

import xml.etree.ElementTree as ET
from optparse import OptionParser


class ParseNgConnFile(object):
    '''
    classdocs
    '''


    def __init__(self):
        '''
        Constructor
        '''
        self.magicStr = "mR3m"
        #self.connFile = "/home/rainman/workspace/python_practice/ParseNgConnFile/confCons.xml"
        self.connFile = os.path.join(os.path.dirname(os.path.abspath(__file__)), "confCons.xml")
        self.key = md5.new(self.magicStr).digest()
        self.et = None
        self.connections = {}
    
    def parse_conn_file(self):
        self.et = ET.parse(self.connFile)
        root = self.et.getroot()
        nodes = root.findall("Node")
        for node in nodes:
            subNodes = node.findall("Node")
            nodeName = node.get("Name")
            self.connections[nodeName] = {}
            for subNode in subNodes:
                name = subNode.get("Name")
                hostName = subNode.get("Hostname")
                user = subNode.get("Username")
                password = self.get_password(subNode.get("Password"))
                protocol = subNode.get("Protocol")
                hostInfo = {"name":name, "host":hostName, "user":user, "password":password}
                if protocol == "SSH2":
                    self.connections[nodeName][name]=hostInfo
    
    def list_all_connections(self):
        for containerName in self.connections:
            print containerName+":"
            for host in self.connections[containerName]:
                hostInfo = self.connections[containerName][host]
                print "    %22s     %s" % (hostInfo["name"], hostInfo["host"])
            #print "\n"
    
    def get_connection_info(self):
        containerName = None
        host = None
        containerNameList = self.connections.keys()
        print "Please select container:"
        index = 1
        for container in containerNameList:
            print "%d %30s" % (index, container)
            index+=1
        #print ""
        containerId = raw_input("Please input:")
        if containerId.isdigit() and int(containerId)>=1 and int(containerId)<=len(containerNameList)+1:
            containerName = containerNameList[int(containerId)-1]
        else:
            print "Input is invalid id"
            return 1
        
        hostList = self.connections[containerName].keys()
        print "Please select host:"
        index = 1
        for name in hostList:
            print "%d %30s" % (index, name)
            index += 1
        hostId = raw_input("Please input:")
        if hostId.isdigit() and int(hostId)>=1 and int(hostId)<=len(hostList)+1:
            host = hostList[int(hostId)-1]
        else:
            print "Input is invalid id"
            return 1        
        
        connections = self.connections[containerName]        
        conn = connections[host]
        hostName = conn["host"]
        user = conn["user"]
        password = conn["password"]
        if user!="" and password!="" and hostName!="":
            result = "sshpass -p %s ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no %s@%s" % (password, user, hostName)
        elif user!="" or password=="":
            result = "ssh %s@%s" % (user, hostName)
        else:
            result = "ssh root@%s" % hostName
        
        f = open("/tmp/myssh.log", "w+")
        f.write(result)
        f.close()                   

            
    
    def get_password(self, encryptPassword):
        if not encryptPassword:
            return ""
        pwdBase64 = base64.b64decode(encryptPassword)
        iv = pwdBase64[:16]
        encryptDigest = pwdBase64[16:]
        decryptor = AES.new(self.key, AES.MODE_CBC, iv)
        password = decryptor.decrypt(encryptDigest)
        if len(password)>0 and (ord(password[-1]) < 33 or ord(password[-1]) > 126):
            #print "delete pattern:"
            password = password.strip(password[-1])
        return password

def main():
    parser = OptionParser()
    parser.add_option("-c", action="store_true", dest="connect",
                  help="select the host which want to connect")
    parser.add_option("-l", action="store_true", dest="verbose")

    (options, args) = parser.parse_args()
    
    connInfo = ParseNgConnFile()
    connInfo.parse_conn_file()
    
    if options.verbose == True:
        connInfo.list_all_connections()
    elif options.connect==True:
        connInfo.get_connection_info()
    
    

if __name__ == "__main__":
    main()
    
        
        
        
        