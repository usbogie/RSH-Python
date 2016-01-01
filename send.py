from socket import *
import os.path, time
import threading
from getpass import getpass

#Not sure if it makes sense to have an init file in the sender method - it would mean you
#can only connect to the rsh from a specific directory, which isn't very similar to how ssh works

def send(ip):

    # Hard coded these values into this file so that the init.ini file doesn't need to 
    # be in the same folder as send.py
    port = 55567
    buf = 1024
    login = getpass(">>> Password: ")
    cmd = str("_login " + login)
    addr = (ip, port)
    exit = False
    loggedIn = False
    while not exit:
        try:
            if 'exit' == cmd:
                exit = True
            #Create a socket that operates on TCP protocol
            clientsocket = socket(AF_INET, SOCK_STREAM)
            clientsocket.connect(addr)
            #socket module only accepts data in bytes, so "encode('ascii')" is necessary
            clientsocket.send(cmd.encode('ascii'))
            #If the user did not quit send, wait for the command response from the server
            if not exit:
                response = clientsocket.recv(buf).decode('ascii')
                if response:
                    if "fail" in response and not loggedIn:
                        loggedIn = False
                    else:
                        loggedIn = True
                if 'Command Executed' != response:
                    print(response)
            clientsocket.close()
        except Exception as e:
            print("Send exception: ",e)
        if not exit:
            if not loggedIn:
                cmd = getpass(">>> Password: ")
                cmd = "_login "+cmd
            else:
                cmd = input(">>> ")

if __name__ == "__main__":
    print("RSH\n")
    ip = input("RSH Address: ")
    send(ip)
