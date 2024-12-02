import requests
import base64
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import os
# TODO: import additional modules as required

gt_username = 'araddatz6'   # TODO: Replace with your gt username within quotes
server_name = 'secure-shared-store'

# These need to be created manually before you start coding.
node_certificate = 'certs/client1.crt'
node_key = 'certs/client1.key'
checkedOutFiles = []
is_login = False
loggedInUser = ''

''' <!!! DO NOT MODIFY THIS FUNCTION !!!>'''
def post_request(server_name, action, body, node_certificate, node_key):
    """
        node_certificate is the name of the certificate file of the client node (present inside certs).
        node_key is the name of the private key of the client node (present inside certs).
        body parameter should in the json format.
    """
    request_url = 'https://{}/{}'.format(server_name, action)
    request_headers = {
        'Content-Type': "application/json"
    }
    response = requests.post(
        url=request_url,
        data=json.dumps(body),
        headers=request_headers,
        cert=(node_certificate, node_key),
        verify="/home/cs6238/Desktop/Project4/CA/CA.crt",
        timeout=(10, 20),
    )
    with open(gt_username, 'wb') as f:
        f.write(response.content)

    return response

''' You can begin modification from here'''

def sign_statement(statement, user_private_key_file):
    keyText = ''
    with open(user_private_key_file, "rb") as file:
        keyText = serialization.load_pem_private_key(file.read(),password=None,)
        #keyText = file.read()
    #print(keyText)  
    stamentB = statement.encode()
    signedSTatement = keyText.sign(stamentB,
                                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                salt_length = padding.PSS.MAX_LENGTH),
                                hashes.SHA256())
    #print(signedSTatement)
    return signedSTatement

def login():
    global loggedInUser
    """
        # TODO: Accept the
         - user-id
         - name of private key file(should be present in the userkeys folder) of the user.
        Generate the login statement as given in writeup and its signature.
        Send request to server with required parameters (Ex: action = 'login') using the
        post_request function given.
        The request body should contain the user-id, statement and signed statement.
    """

    successful_login = False

    while not successful_login:
        # get the user id from the user input or default to user1
        try:
            user_id = (input(" User Id: ") )#user_id = (input(" User Id: ") or "user1")
        except Exception as e:
            pass


        # get the user private key filename or default to user1.key
        private_key_filename = (input(" Private Key Filename: ") or "user1.key")

        # complete the full path of the user private key filename (depends on the client)
        # Ex: '/home/cs6238/Desktop/Project4/client1/userkeys/' + private_key_filename
        user_private_key_file = '/home/cs6238/Desktop/Project4/client1/userkeys/' + private_key_filename

        # create the statement
        statement = node_key + ' as ' + user_id + ' logs into the Server'
        signed_statement = sign_statement(statement, user_private_key_file)

        body = {
            'user-id': user_id,
            'statement': statement,
            'signed-statement': base64.b64encode(signed_statement).decode("utf8")
        }

        server_response = post_request(server_name, 'login', body, node_certificate, node_key)

        if server_response.json().get('status') == 200:
            successful_login = True
            loggedInUser = user_id
            #print(f'loggedInUser{loggedInUser}')
        else:
            print(server_response.json().get('message', "Try again"))

    return server_response.json()


def checkin(session_token):
    """
        # TODO: Accept the
         - DID: document id (filename)
         - security flag (1 for confidentiality  and 2 for integrity)
        Send the request to server with required parameters (action = 'checkin') using post_request().
        The request body should contain the required parameters to ensure the file is sent to the server.
    """
    fileName = (input(" File Name: ") or "file1.txt")
    securityFlag = (input(" Security Flag: ") or "1")
    filePath = '/home/cs6238/Desktop/Project4/client1/documents/checkin/' + fileName
    if fileName in checkedOutFiles:
        #os.replace('/home/cs6238/Desktop/Project4/client2/documents/checkout/' + fileName,filePath)
        if os.path.exists('/home/cs6238/Desktop/Project4/client1/documents/checkout/' + fileName):
                print('about to remove a file')
                try:
                    os.replace('/home/cs6238/Desktop/Project4/client1/documents/checkout/' + fileName,filePath)
                    #print(f'{file2} for user:{loggedInUser}')
                except Exception as e:
                    print('no file')
    try:
        #except Exception as e:
        
        with open(filePath, "r") as file:
        
            filecontents = file.read()
            print(f'contents of {fileName} : {filecontents}')
            
            body = {
                'user-id': loggedInUser,
                'fileName': fileName,
                'fileContents': filecontents,
                'token' : session_token,
                'flag' : securityFlag
            }

            server_response = post_request(server_name, 'checkin', body, node_certificate, node_key)

            if server_response.json().get('status') == 200:
                print('File Created Successfully')
            else:
                print(server_response.json().get('message', "Try again"))
    except Exception as e:
        print(f'file not found {e}')
    #Need to check if the file exists
    #if it does, open and send the contents with the token

    return


def checkout(session_token):
    """
        # TODO:
        Send request to server with required parameters (action = 'checkout') using post_request()
    """
    fileName = (input(" File Name: ") or "file1.txt")
    body = {
                'user-id': loggedInUser,
                'fileName': fileName,
                'token' : session_token
            }
    server_response = post_request(server_name, 'checkout', body, node_certificate, node_key)

    if server_response.json().get('status') == 200:
        print('File Retrieved Successfully')
        data = server_response.json()
        file = data['file']
        filePath = '/home/cs6238/Desktop/Project4/client1/documents/checkout/' + fileName
        filewrite =  open(filePath, "w") 
        filewrite.write(file)
        checkedOutFiles.append(fileName)
    else:
        print(server_response.json().get('message', "Try again"))
    return


def grant(session_token):
    global loggedInUser
    """
        # TODO:
         - DID
         - target user to whom access should be granted (0 for all user)
         - type of access to be granted (1 - checkin, 2 - checkout, 3 - both checkin and checkout)
         - time duration (in seconds) for which access is granted
        Send request to server with required parameters (action = 'grant') using post_request()
    """
    fileName = (input(" File Name: ") or "file1.txt")
    targetUser = (input(" Target User: ") or "user2")
    accessRight = (input(" Access Right: ") or "1")
    time = (input(" Time: ") or "50")

    body = {
                'user-id': loggedInUser,
                'fileName': fileName,
                'targetUser': targetUser,
                'accessRight': accessRight,
                'time': time,
                'token' : session_token
            }
    server_response = post_request(server_name, 'grant', body, node_certificate, node_key)
    if server_response.json().get('status') == 200:
        print('permission granted successfully')
    return


def delete(session_token):
    """
        # TODO:
        Send request to server with required parameters (action = 'delete')
        using post_request().
    """
    fileName = (input(" File Name: ") or "file1.txt")
    body = {
                'user-id': loggedInUser,
                'fileName': fileName,
                'token' : session_token
            }

    server_response = post_request(server_name, 'delete', body, node_certificate, node_key)

    if server_response.json().get('status') == 200:
         print('File Deleted Successfully')
    else:
         print(server_response.json().get('message', "Try again"))
    return


def logout(session_token):
    global loggedInUser, is_login 
    """
        # TODO: Ensure all the modified checked out documents are checked back in.
        Send request to server with required parameters (action = 'logout') using post_request()
        The request body should contain the user-id, session-token
    """
    for file2 in checkedOutFiles:
        print(f'{file2}111 for user:{loggedInUser}')
        if os.path.exists('/home/cs6238/Desktop/Project4/client1/documents/checkout/' + file2):
            try:
                os.replace('/home/cs6238/Desktop/Project4/client1/documents/checkout/' + file2,'/home/cs6238/Desktop/Project4/client1/documents/checkin/' + file2)
                print(f'{file2} for user:{loggedInUser}')
            except Exception as e:
                print('no file')
        filePath = '/home/cs6238/Desktop/Project4/client1/documents/checkin/' + file2
        with open(filePath, "r") as file:
        
            filecontents = file.read()
            #print(f'contents of {file} : {filecontents}')
            
           # body = {
           ##     'user-id': loggedInUser,
            #    'fileName': file2,
            #    'fileContents': filecontents,
            #    'token' : session_token,
            #    'flag' : 2
           # }

            #server_response = post_request(server_name, 'checkin', body, node_certificate, node_key)

 #           if server_response.json().get('status') == 200:
#                print('File Created Successfully')
  #          else:
   #             print(server_response.json().get('message', "Try again"))
    body = {
                'user-id': loggedInUser,
                'token' : session_token
            }
    
    server_response = post_request(server_name, 'logout', body, node_certificate, node_key)
    if server_response.json().get('status') == 200:
        print('Logged Out Successfully')
        is_login = False
    else:
        print(server_response.json().get('message', "Try again"))

    return


def print_main_menu():
    """
    print main menu
    :return: nothing
    """
    print(" Enter Option: ")
    print("    1. Checkin")
    print("    2. Checkout")
    print("    3. Grant")
    print("    4. Delete")
    print("    5. Logout")
    return


def main():
    global is_login
    """
        # TODO: Authenticate the user by calling login.
        If the login is successful, provide the following options to the user
            1. Checkin
            2. Checkout
            3. Grant
            4. Delete
            5. Logout
        The options will be the indices as shown above. For example, if user
        enters 1, it must invoke the Checkin function. Appropriate functions
        should be invoked depending on the user input. Users should be able to
        perform these actions in a loop until they logout. This mapping should
        be maintained in your implementation for the options.
    """

    # Initialize variables to keep track of progress
    server_message = 'UNKNOWN'
    server_status = 'UNKNOWN'
    session_token = 'UNKNOWN'
    

    # test()
    # return
    login_return = login()

    server_message = login_return['message']
    server_status = login_return['status']
    session_token = login_return['session_token']

    print("\nThis is the server response")
    print(server_message)
    print(server_status)
    print(session_token)

    if server_status == 200:
        is_login = True

    while is_login:
        print_main_menu()
        user_choice = input()
        if user_choice == '1':
            checkin(session_token)
        elif user_choice == '2':
            checkout(session_token)
        elif user_choice == '3':
            grant(session_token)
        elif user_choice == '4':
            delete(session_token)
        elif user_choice == '5':
            logout(session_token)
        else:
            print('not a valid choice')


if __name__ == '__main__':
    main()
