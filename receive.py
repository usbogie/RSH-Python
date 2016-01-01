from socket import *
import os.path, time
from os import fork, execvp, waitpid, dup2, close
from sys import exit
import threading
from configparser import ConfigParser
import errno
from hashlib import sha224


def handler(clientsocket, clientaddr, password, loggedin_ips):
    while True:
        try:
            # Receive data from client
            data = clientsocket.recv(1024).decode('ascii')
        except Exception as e:
            # If the program reaches here, it is due to a "Connection reset by Peer" error
            # As instructed, we pass over this error
            pass
        if not data:
            break

        #If this IP address has not been seen before or there are 0 logged in
        #session from this IP address, check if they entered a correct password
        if clientaddr[0] not in loggedin_ips or loggedin_ips[clientaddr[0]] == 0:

            # Encrypt incoming password with same key as the password in init.ini
            m = sha224()
            m.update(data[len('_login')+1:].encode('utf-8'))
            if m.hexdigest() == password:
                loggedin_ips[clientaddr[0]] = 1
                clientsocket.send("Authentication successful".encode('ascii'))
            else:
                clientsocket.send("Authentication failed. Please reenter password".encode('ascii'))
        else:
            try:
                cmd = str(data).split()
                status = int()
                #exit is sent only when send.py is exited, thus we decrement
                #the logged in session of the IP address by 1
                if 'exit' == cmd[0]:
                    loggedin_ips[clientaddr[0]] = loggedin_ips[clientaddr[0]] - 1
                #If a client connected from a computer already logged in, the clients
                #first mandatory password message must be disregarded, and we update the
                #login count for this IP address
                elif data.startswith('_login'):
                    loggedin_ips[clientaddr[0]] = loggedin_ips[clientaddr[0]] + 1
                    clientsocket.send("already logged in\n".encode('ascii'))
                else:
                    try:
                        # Get the socket file descriptor to write to in dup2
                        socket_fd = clientsocket.fileno()
                    except Exception as e:
                        print(e)
                    pid = fork()
                    if pid < 0:
                        raise Exception("Fork failed")
                    # Child process
                    elif pid == 0:
                        try:
                            # Set the socket to be the output instead of the receive.py output
                            dup2(socket_fd, 0)
                            dup2(socket_fd, 1)
                            dup2(socket_fd, 2)
                            execvp(cmd[0],cmd)
                        except Exception as e:
                            print(e)
                    # Parent process
                    else:
                        try:
                            x, stat = waitpid(pid, status)
                            if x < 0:
                                raise Exception("Child Process Error")
                        except Exception as e:
                            print(e)
                    clientsocket.send("Command Executed".encode('ascii'))
            except IOError as e:
                # if this if statement is true, there is a Broken Pipe error, which didn't 
                # affect how the program ran. As instructed, this exception is passed 
                if e.errno == errno.EPIPE:
                    pass
    clientsocket.close()

#This method listens at a specific port for socket connections
#When a connection is made, receive creates a thread. The thread calls the
#handler function with the given arguments
#Note: Due to Python's Global Interpreter Lock, only one thread can execute at once
#However, in this case threading is still useful because it allows multiple IO bound
#tasks to be run simultaneously
def receive():

    # create ConfigParser to read from init.ini file
    config = ConfigParser()
    config.read("init.ini")
    
    # extract port and buf values from init.ini file
    port = int(config["DEFAULT"]["port"])
    buf = int(config["DEFAULT"]["buf"])

    # if PASSWORD section exists, get password, else proceed to else statement 
    try:
        password = config["PASSWORD"]["password"]
    except:
        # prompt user to set a new password
        print("There is no password set for this process. Would you like to set one?[y/n]")
        response = input(">>> ")

        if response.lower().startswith("y"):
            print("Please enter new password")
            newPass = input(">>> ")

            # hash the new password input
            password = sha224(newPass.encode('utf-8')).hexdigest()
            if not config.has_section("PASSWORD"):
                config.add_section("PASSWORD")
            config.set("PASSWORD","password",password)

            #write the new items in the configparser to init.ini
            with open("init.ini",'w') as cfgfile:
                config.write(cfgfile)
                print("Password set successfully\n")
        else:
            return

    #Default address is the local computer's IP address
    addr = ('', port)

    #Creates a socket that uses TCP protocal
    serversocket = socket(AF_INET, SOCK_STREAM)

    #Bind the server to the local IP address and port
    serversocket.bind(addr)

    print("Listening for connections...")
    
    #Listen for connections made to the socket
    serversocket.listen(1)

    #A dictionary to keep track of the IP addresses of the connections that have
    #successfuly logged in. The dictionary keeps track of a count so that if one computer
    #makes multiple connections, the corresonding IP address will not be logged out until
    #all sessions have ended
    loggedin_ips = {}

    while True:
        clientsocket, clientaddr = serversocket.accept()
        thread = threading.Thread(target=handler, args=(clientsocket, clientaddr, password, loggedin_ips))
        thread.start()

    #close the socket when finished
    serversocket.close()

if __name__ == "__main__":
    receive()
