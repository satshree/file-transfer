import socket
import sys
import subprocess
import EncryptDecrypt
from tkinter.filedialog import askopenfilename
from base64 import b64encode
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

    try:
        key = input("Enter your key for encryption/decryption: ")
    except KeyboardInterrupt:
        print("\n\nExiting \n")
        exit(0)

    # Hash the given key
    safe_key = EncryptDecrypt.generatekey(key)

    return safe_key

def print_banner(port, ip, local):
    """ This is the banner. """
    print("")
    print("-" * 60)
    print("SHARE ANY FILES THROUGH INTERNET")
    print("-" * 60)

    print("You can send files to the client that connects to you.")
    print("Client machine must be in the same network as the server.")
    print("\nYour files will be encrypted on the network to keep it safe.")
    print("For the encryption you will have to provide a safe key.")
    print("### MAKE SURE SERVER AND CLIENT USES SAME KEY ###")

    print("-" * 60)
    print("This is server side.")
    if local:
        print("\nTo connect,\n\nUse port number =", port, "\nUse IP address = 127.0.0.1 OR 'local'")
    else:
        print("\nTo connect,\n\nUse port number =", port, "\nUse IP address =", get_ip_address())
    

def check_key(connection, safe_key):
    """ This will check for correct key. """

    print("-" * 60)
    print("Waiting for client to verify key...")
    
    while True:
        connection.send(EncryptDecrypt.encipher("TEST", safe_key))
        test = connection.recv(1).decode('utf-8')
        if test == "B":
            print("Key verified")
            break
        else:
            pass     

def start_server(port, local):
    """ This will start a server and start sharing files. """

    encrypted__segment = []

    # Check for local host
    if local:
        ip='127.0.0.1'
    else:
        ip=get_ip_address()

    # Print banner
    print_banner(port, ip, local)

    print("-" * 60)
    # Ask user for key
    safe_key = ask_key()

    # Declare file types for sharing
    filetypes = (
        ("All Files", "*.*"),
        ("JPEG", "*.jpg"),
        ("PNG", "*.png"),
        ("MP3", "*.mp3"),
        ("MP4", "*.mp4"),
        ("MOV", "*.mov"),
        ("M4A", "*.m4a"),
        ("DOCX", "*.docx")
    )

    # try:
    # Start a TCP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Start a TCP server
    sock.bind((ip,port))

    # Listen for ONE client
    sock.listen(1)

    print("-" * 60)
    print("Server hosted at Port:", port, "and IP:",  ip)
    print("-" * 60)

    # Accept a connection from client
    connection, address = sock.accept()

    print("Incoming connection from:", address[0])
    print("-" * 60)
    print("Connection established with", address[0])
    check_key(connection, safe_key)
    while True:
        print("-" * 60)
        enter = input("Press Enter to select files to send.")
        
        print("-" * 60)
        print("Selecting a file....")

        # Select a file through a dialog box
        file = askopenfilename(initialdir="/", filetypes =(filetypes), )

        # Get the filename.extension
        filename = file.split("/").pop()

        print("-" * 60)
        print("File", filename, "selected.")

        # Read the actual file and buffer size to send.
        binary_file = open(file, "br")
        read_file = binary_file.read()
        encoded_data = b64encode(read_file)

        print("-" * 60)
        print("Encrypting your file...")
        print("-" * 60)
        # Encrypt the file segment by segment 
        to_send_loop_time = 0
        total_progress = int(len(encoded_data.decode('utf-8'))/900) + 1

        try:
            for loop in range(0, len(encoded_data.decode('utf-8')), 900):
                file_segment = encoded_data.decode('utf-8')[loop:loop+900]
                encrypted_segment = EncryptDecrypt.encipher(file_segment, safe_key)
                encrypted__segment.append(encrypted_segment.decode('utf-8'))
                to_send_loop_time += 1
                print("\rProgress: {} % | Encrypting segment: {} | Total Segments to Encrypt: {}".format(int((to_send_loop_time/total_progress)*100), to_send_loop_time, total_progress), end="")
        except KeyboardInterrupt:
            print("\n\nExiting\n")
            exit(0)

        print("")
        print("-" * 60)
        print("Sending....")
        print("-" * 60)
        # for i in encrypted__segment:
        #     print("")
        #     print(i)
        progress = 1
        while True:
            try:
                # Start sending the file
                receive_prompt = connection.recv(10000).decode('utf-8')
            except:
                print("Connection Lost ....")
                return
            
            # Decrypt prompt
            do_what = EncryptDecrypt.decipher(receive_prompt, safe_key).decode('utf-8')
            
            if do_what == "buffer":
                # Send buffer size to client
                buffer_size = str(len(encrypted__segment[0]))
                connection.send(EncryptDecrypt.encipher(buffer_size, safe_key))
            elif do_what == "filename":
                # Send filename to client
                connection.send(EncryptDecrypt.encipher(filename, safe_key))
            elif do_what == "loop":
                # Send loop number to client
                connection.send(EncryptDecrypt.encipher(str(to_send_loop_time), safe_key))
            elif do_what == "file":
                # Send actual file to client
                for i in range(to_send_loop_time):
                    connection.send(encrypted__segment[i].encode())
                    connection.recv(1)
                    print("\rProgress: {} %".format(int((progress/to_send_loop_time)*100)), end="")
                    progress += 1

            elif do_what == "end":
                # End the process
                break
        
        print("")
        print("-" * 60)
        print("File", filename, "sent.")
        print("-" * 60)

        # Close the file
        binary_file.close()

        while True:
            try:
                send_more = input("Do you want to send more file?[y/n]: ")
                if send_more.lower() == "y" or send_more.lower() == "yes":
                    # Tell client to not close the connection
                    connection.send(b'A')
                    break
                elif send_more.lower() == "n" or send_more.lower() == "no":
                    print("-" * 60)
                    print("Closing connection with", address[0])
                    # Tell client to close the connection
                    connection.send(b'B')
                    sock.close()
                    return
                else:
                    print("-" * 60)
                    print("Enter either 'y' for yes or 'n' for no.")
                    print("-" * 60)
            except:
                print("-" * 60)
                print("Try again")
                print("-" * 60)
        
    # except Exception as e:
    #     print("Something went wrong.")
    #     print("Error detail:", e)


if __name__ == "__main__":

    while True:
        print("-" * 60)
        print("First steps to start a simple TCP server,")
        print("-" * 60)
        print("Default port: 6548\n")

        try:
            # Ask user to host a server on a custom port or default
            port = input("Custom port for a server?[y/n]: ")
            if port.lower() == "y" or port.lower() == "yes":
                port_no = int(input("Enter a random number to host a server: "))
                if port_no <= 1024:
                    print("Custom port cannot be below 1024.")
                    raise EOFError

            elif port.lower() == "n" or port.lower() == "no":
                pass
            else:
                raise EOFError
            
            # Ask user to host a server on locally or publicly
            localip = input("Host on a local IP?[y/n]: ")
            if localip.lower() == "y" or localip.lower() == "yes":
                local=True
            elif localip.lower() == "n" or localip.lower() == "no":
                local=False
            else:
                raise EOFError

            break
        except KeyboardInterrupt:
            print("Closed")
            exit(0)
        except EOFError:
            print("Try Again.")
        except Exception as e:
            print("Something went wrong.\nError Details:", e)

            
    if port.lower() == "n" or port.lower() == "no":
        port_no = 6548
        start_server(port_no, local)
    else:
        start_server(port_no, local)

    print("-" * 60)
    print("Made by Satshree Shrestha")
    print("-" * 60)

    enter = input("Press Enter to exit.")
    exit(0)


        

        
        
    
