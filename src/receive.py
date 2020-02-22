import socket
import subprocess
import sys
import os
import EncryptDecrypt
from tkinter.filedialog import asksaveasfile 
from base64 import b64decode
# import urllib.request as url
__author__ = "Satshree Shrestha"


def get_ip_address():
    """ This will retrieve the IP address of the system. """

    # For Windows system
    if sys.platform == 'win32':
        # Run Command Prompt command, decode it and split it into list
        command = subprocess.check_output(['ipconfig']).decode('utf-8').split()

        for index in range((len(command)-1), 0, -1):
            if command[index] == 'Subnet':
                ip_address = command[index-1]
                break
    else:
        # Get the hostname of the system
        system_hostname = socket.gethostname()

        # Get IP address of the system
        ip_address = socket.gethostbyname(system_hostname)
    
    # ip_address = url.urlopen('http://ip.42.pl/raw').read().decode('utf-8')
    
    return ip_address

def ask_key():
    """ This will ask key to user for encryption/decryption. """

    key = input("Enter your key for encryption/decryption: ")

    # Hash the given key
    safe_key = EncryptDecrypt.generatekey(key)

    return safe_key

def check_key(sock, safe_key):
    """ This will check for correct key. """

    print("-" * 60)
    print("Checking if the key matches with server...")
    
    while True:
        test = EncryptDecrypt.decipher(sock.recv(1000).decode('utf-8'), safe_key)

        if test == 0:
            print("-" * 60)
            print("KEY DOES NOT MATCH WITH THE SERVER!") 
            print("-" * 60)
            safe_key = ask_key()
            sock.send(b'A')
        else:
            print("-" * 60)
            print("Key matches with server.")
            print("-" * 60)
            sock.send(b'B')
            break
    
    return safe_key

def print_banner(port, ip):
    """ This is a banner """
    print("")
    print("-" * 60)
    print("SHARE ANY FILES THROUGH INTERNET")
    print("-" * 60)

    print("You will receive files from the server that you connect to.")
    print("Server must be in the same network as client.")
    print("Your files will be encrypted on the network to keep it safe.")
    print("For encryption, you have to provide the same key server is using.")
    print("### MAKE SURE SERVER AND CLIENT USE SAME KEY ###")

    print("-" * 60)
    print("This is client side.\n")
    print("Client description,")
    print("IP: %s" % get_ip_address())
    print("Connecting to server:", ip)
    
def connect_server(port, ip):
    """ This will connect to server and receive files. """
    
    final_data = []
    final_decrypted_data = []

    # Check for local
    if ip.lower() == "local":
        ip = '127.0.0.1'

    # Print banner
    print_banner(port, ip)
    
    while True:
        try:
            print("-" * 60)
            print("Establishing connection with", ip)
            # Start a TCP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Start connection with server
            sock.connect((ip,port))

            break
        except:
            print("-" * 60)
            print("Connection failed")
            print("-" * 60)
            try_again = input("Try Again? [y/n]: ")
            if try_again.lower() in ('y', 'yes'):
                continue
            else:
                return

    print("-" * 60)
    # Ask user for key
    safe_key = ask_key()

    # try:
    print("-" * 60)
    print("Connection to", ip, "successful")

    # Check for correct key
    safe_key = check_key(sock, safe_key)
    
    while True:
        print("Listening to", ip)
        print("-" * 60)

        try:
            # Tell server to send buffer size
            sock.send(EncryptDecrypt.encipher("buffer", safe_key))
            buffer_size = int(EncryptDecrypt.decipher(sock.recv(1000).decode('utf-8'), safe_key).decode('utf-8'))

            # Tell server to send filename
            sock.send(EncryptDecrypt.encipher("filename", safe_key))
            filename = EncryptDecrypt.decipher(sock.recv(10000).decode('utf-8'), safe_key).decode('utf-8')

            # Tell server to send number of loops to receive file
            sock.send(EncryptDecrypt.encipher("loop", safe_key))
            loop = int(EncryptDecrypt.decipher(sock.recv(10000).decode('utf-8'), safe_key).decode('utf-8'))

            # Tell server to send actual file
            sock.send(EncryptDecrypt.encipher("file", safe_key))
        except:
            print("Connection Lost ....")
            return

        print('Receiving file "{}" from {}'.format(filename, ip))
        print("-" * 60)
        progress = 1
        for i in range(loop):
            data = sock.recv(buffer_size).decode('utf-8')
            final_data.append(data)
            sock.send(b'7')
            print("\rProgress: {} %".format(int((progress/loop)*100)), end="")
            progress += 1
        
        print("")
        print("-" * 60)
        print("Decrypting received file...")
        print("-" * 60)
        # Decrypt data
        progress = 1

        try:
            for i in range(loop):
                # print(i)
                final_decrypted_data.append(EncryptDecrypt.decipher(final_data[i], safe_key).decode('utf-8'))
                print("\rProgress: {} %".format(int((progress/loop)*100)), end="")
                progress += 1
        except KeyboardInterrupt:
            print("\n\nExiting\n")
            exit(0)

        print("")
        final__data = ''.join(final_decrypted_data)
        
        # Decode data 
        decrypted_data = b64decode(final__data)
        
        # End the process
        sock.send(EncryptDecrypt.encipher("end", safe_key))

        print("-" * 60)
        print("File", filename, "received.")
        print("-" * 60)

        while True:
            try:
                # Ask user to save the file on current directory or different directory
                save_file = input("Save received file to current directory?[y/n]: ")

                if save_file.lower() == "n" or save_file.lower() == "no":
                    print("-" * 60)
                    print("Selecting a directory...")

                    # Ask user where to save the received file
                    file_path = asksaveasfile(mode="w", confirmoverwrite=True, initialfile=filename, filetypes=[("All Files", ".*")])

                    if file_path.name == "":
                        # If user cancels the request, save the file to current directory
                        write_file = open(filename, "bw")
                        print("-" * 60)
                        print("File will be saved to current directory at,\n>>", os.path.dirname(os.path.realpath(__file__)))
                    else:
                        # Create the file where user has specified
                        write_file = open(file_path.name, "bw")
                        
                elif save_file.lower() == "y" or save_file.lower() == "yes":
                    # Saving the file on current directory
                    write_file = open(filename, "bw")
                    print("-" * 60)
                    print("File will be saved to current directory at,\n>>", os.path.dirname(os.path.realpath(__file__)))
                else:
                    print("Enter either 'y' for yes or 'n' for no.")
                    raise Exception 

                print("-" * 60)
                print("Saving...")
                # Saving received file
                write_file.write(decrypted_data)
                write_file.close()
                print("-" * 60)
                print("File saved!")
                break
            except Exception as e:
                print("Try Again.", e)
        
        print("-" * 60)
        print("Listening to", ip)
        print("-" * 60)
        if sock.recv(1).decode('utf-8') == 'A':
            # If server wants to send more files
            print("Server responded to send another file.")
            pass
        else:
            # If server does not want to send more files
            print("Server responded to stop sending files.")
            print("Closing connection with", ip)
            sock.close()
            break
    # except Exception as e:
    #     print("Something went wrong")
    #     print("Error detail:", e)


if __name__ == "__main__":
    print("-" * 60)
    print("First steps to connect to a simple TCP server,")
    print("-" * 60)
    print("Default port: 6548\n")

    while True:
        try:
            # Ask the user if the server has custom port
            port = input("Does server has custom port?[y/n]: ")
            if port.lower() == "y" or port.lower() == "yes":
                port_no = int(input("Enter a port number to connect to a server: "))
            elif port.lower() == "n" or port.lower() == "no":
                pass
            else:
                raise EOFError

            # Ask the user to connect to the server
            ip = input("Enter server's IP address to connect: ")
            break
        except KeyboardInterrupt:
            print("Closed")
            exit(0)
        except EOFError:
            print("Try Again.")
        except Exception:
            print("Something went wrong.")

    if port.lower() == "n" or port.lower() == "no":
        port_no = 6548
        connect_server(port_no,ip)
    else:
        connect_server(port_no,ip)

    print("-" * 60)
    print("Made by Satshree Shrestha")
    print("-" * 60)

    enter = input("Press Enter to exit.")
    exit(0)
