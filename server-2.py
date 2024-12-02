from flask import Flask, request, jsonify
from flask_restful import Resource, Api
# TODO: import additional modules as required
import base64
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
import os
from datetime import datetime, timedelta
secure_shared_service = Flask(__name__)
api = Api(secure_shared_service)

loggedInUsers = {}
checkedInFiles = {}
listOfGrants = []
#('dummy','dummy','dummy',datetime.now())
class welcome(Resource):
    def get(self):
        return "Welcome to the secure shared server!"

def verify_statement(statement, signed_statement, user_public_key_file):
    #keyText = ''
    try:
        with open(user_public_key_file, "rb") as file:
            keyText = serialization.load_pem_public_key(file.read())
            #keyText = file.read()
            print(f' here is the statement{statement}')  
            stamentB = statement.encode()
            signedSTatement = keyText.verify(
            #statement,
             #                               data=stamentB,
                                            
                                        signature=signed_statement,
                                        data=stamentB,
                                        padding=padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                    salt_length = padding.PSS.MAX_LENGTH),
                                        algorithm=hashes.SHA256())
        return True                               
    except Exception as e:
        return False
    


class login(Resource):
    def post(self):
        print('we are here')
        data = request.get_json()
        print(f'data{data}')
        # TODO: Implement login functionality
        '''
            # TODO: Verify the signed statement.
            Response format for success and failure are given below. The same
            keys ('status', 'message', 'session_token') should be used.
            Expected response status codes:
            1) 200 - Login Successful
            2) 700 - Login Failed
        '''
        # Information coming from the client
        user_id = data['user-id']
        statement = data['statement']
        signed_statement = base64.b64decode(data['signed-statement'])
        print(f'user_id{user_id}')
        # complete the full path of the user public key filename
        # /home/cs6238/Desktop/Project4/server/application/userpublickeys/{user_public_key_filename}
        user_public_key_file = '/home/cs6238/Desktop/Project4/server/application/userpublickeys/' + user_id + '.pub'
        print(f'user_public_key_file{user_public_key_file}')
        success = verify_statement(statement, signed_statement, user_public_key_file)

        if success:
            digest = hashes.Hash(hashes.SHA256())
            digest.update(signed_statement)
            sessionToken = digest.finalize()
            # Similar response format given below can be used for all the other functions
            response = {
                'status': 200,
                'message': 'Login Successful',
                'session_token': sessionToken.hex(),
            }
            loggedInUsers[sessionToken.hex()] = user_id
        else:
            response = {
                'status': 700,
                'message': 'Login Failed',
                'session_token': "INVALID",
            }
        return jsonify(response)



class checkin(Resource):

    def saveFile(self,user, fileName, fileContents, flag):
        fileContentsFinal = ''
        encryptedKey = ''
        fileHash = ''
        filePath = '/home/cs6238/Desktop/Project4/server/application/documents/' + fileName
        if flag == "1":
            with open(filePath, "w") as file:
                #print(f'----------fileContentsFinal{fileContentsFinal2}')
                file.write('')
            fileKey = Fernet.generate_key()
            #print(f'fileKey{fileKey} len: {len(fileKey)}')
            f = Fernet(fileKey)
            fileContentsBytes = fileContents.encode()
            fileContentsFinal2= f.encrypt(fileContentsBytes)
            #fileContentsFinal = base64.b64encode(fileContentsFinal2).decode()
            #print(f'fileContentsFinal{fileContentsFinal}')
            f2 = Fernet(fileKey)
            #text123123 = f2.decrypt(fileContentsFinal2)
            #print(f'text123123{text123123}')
            #need to encrypt key and store file metadata
            keyText = ''
            with open('/home/cs6238/Desktop/Project4/server/certs/secure-shared-store.pub', "rb") as file:
                keyText = serialization.load_pem_public_key(file.read())
                #keyText = file.read()
            #print(keyText)  
            #stamentB = fileKey.encode()
            encryptedKey = keyText.encrypt(fileKey,
                                        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                        label=None,
                                        algorithm=hashes.SHA256()))
            
            with open(filePath, "wb") as file:
                #print(f'----------fileContentsFinal{fileContentsFinal2}')
                file.write(fileContentsFinal2)
        else:
            fileContentsFinal2 = fileContents
            fileHash = hash(fileContents)
            #filePath = '/home/cs6238/Desktop/Project4/server/application/documents/' + fileName
            with open(filePath, "w") as file:
                #print(f'----------fileContentsFinal{fileContentsFinal2}')
                file.write(fileContentsFinal2)
        #if fileName not in checkedInFiles.values():
        checkedInFiles[fileName] = (user,encryptedKey,fileHash)#base64.b64encode(encryptedKey).decode('utf-8')
        print(f'the new entry is {checkedInFiles[fileName]}')
    """
    TODO: Need to handle someone with permission to modify
    Expected response status codes:
    1) 200 - Document Successfully checked in
    2) 702 - Access denied checking in
    3) 700 - Other failures
    """
    #need to check if the file exists
    #if it does, load the contents and post it


    def post(self):
        data = request.get_json()   
        token = data['token']
        fileName = data['fileName']
        user_id = data['user-id']
        fileContents = data['fileContents']
        flag = data['flag']
        print(f'contents of {fileName} : {fileContents}')
        filePath = '/home/cs6238/Desktop/Project4/server/application/documents/' + fileName
        success = False
        status = 700
        #check if user is logged in
        if token in loggedInUsers:
            #if the file is checked in, need to make sure the owner is modifying it
            if fileName in checkedInFiles:
                print('here1'   )
                if checkedInFiles[fileName][0] == user_id:
                    print('here2')
                    success = True
                    self.saveFile(user_id,fileName,fileContents,flag)
                    #file =  open(filePath, "w") 
                    #file.write(fileContents)
                #else this is not the owner
                else:
                    status = 702
                    for tupleGrant in listOfGrants:#or tupleGrant[0] == '0'
                        if (tupleGrant[0] == user_id or tupleGrant[0] == '0')and tupleGrant[1] == fileName: 
                            if datetime.now() <= tupleGrant[3] and (tupleGrant[2] == '1' or tupleGrant[2] == '3'):
                                success = True
                                self.saveFile(checkedInFiles[fileName][0],fileName,fileContents,flag)
                                #status = 702
                            else:
                                break
                            break
                    #success = False
            #new file, go ahead and create
            else:
                self.saveFile(user_id,fileName,fileContents,flag)
                #file =  open(filePath, "w") 
                #file.write(fileContents)
                success = True
                print(f'contents of {filePath} : {fileContents}')
        if success:
            #checkedInFiles[fileName] = user_id
            response = {
                'status': 200,
                'message': 'Document Successfully checked in',
            }
        else:
            response = {
                'status': status,
                'message': 'Access denied checking in',
            }
        return jsonify(response)


class checkout(Resource):


    def getFileContents(self,fileName):
        fileMetadata = checkedInFiles[fileName]
        fileKeyEncrypted = fileMetadata[1]
        fileHash = fileMetadata[2]
        filePath = '/home/cs6238/Desktop/Project4/server/application/documents/' + fileName
        
        #print(f'text{text}')
        if fileKeyEncrypted != '':
            #decrypt key
            file = open(filePath,"rb")
            text = file.read()
            with open('/home/cs6238/Desktop/Project4/server/certs/secure-shared-store.key', "rb") as file:
                keyText = serialization.load_pem_private_key(file.read(),password=None)
                normalKey = keyText.decrypt(fileKeyEncrypted,
                                        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                        label=None,
                                        algorithm=hashes.SHA256()))
                #print(f'fileKeyEncrypted{fileKeyEncrypted} len: {len(fileKeyEncrypted)}')
                #print(f'normalKey{normalKey}')
                
                #b64key = base64.urlsafe_b64encode(fileKeyEncrypted)
                fernetCipher = Fernet(normalKey)
                
            #decrypt file
                fileContents = fernetCipher.decrypt(text).decode()

            
        else:
            file = open(filePath,"r")
            text = file.read()
            if hash(text) == fileHash:
                fileContents = text
            
            else:
                fileContents = 703
            #need to check signature
        print(f'DONEEEEEEEEE {fileContents}')
        return fileContents
        
        
    """
    Expected response status codes
    1) 200 - Document Successfully checked out
    2) 702 - Access denied checking out
    3) 703 - Check out failed due to broken integrity
    4) 704 - Check out failed since file not found on the server
    5) 700 - Other failures
    """
    def post(self):
        data = request.get_json()
        token = data['token']
        fileName = data['fileName']
        user_id = data['user-id']
        success = False
        filePath = '/home/cs6238/Desktop/Project4/server/application/documents/' + fileName
        status = 700
        #this means users is logged in
        if token in loggedInUsers:
            print('here1')
            #this means the file is checked in
            if fileName in checkedInFiles:
                status = 702
                print('here2')
                #this means this user created the file
                if checkedInFiles[fileName][0] == user_id:
                    print(f'user_id{user_id} requesting{fileName}: {checkedInFiles[fileName]}')
                    success = True
                    text = self.getFileContents(fileName)
                    status = 703
                    #file = open(filePath,"r")
                    #text = file.read()
                else:
                    for tupleGrant in listOfGrants:
                        if (tupleGrant[0] == user_id or tupleGrant[0] == '0') and tupleGrant[1] == fileName: 
                            if datetime.now() <= tupleGrant[3] and (tupleGrant[2] == '3' or tupleGrant[2] == '2'):
                                success = True
                                text = self.getFileContents(fileName)
                                status = 703
                            break
            else:
                status = 704 #file not found
        if success and text != 703:
            # Similar response format given below can be
            # used for all the other functions
            response = {
                'status': 200,
                'message': 'Document Successfully checked out',
                'file': text,
            }
        else:
            response = {
                'status': status,
                'message': 'Access denied checking out',
                'file': 'Invalid',
            }
        return jsonify(response)

class grant(Resource):
    """
        Expected response status codes:
        1) 200 - Successfully granted access
        2) 702 - Access denied to grant access
        3) 700 - Other failures
    """
    def post(self):
        data = request.get_json()
        token = data['token']
        loggedInUser = data['user-id']
        fileName = data['fileName']
        targetUser = data['targetUser']
        accessRight = data['accessRight']
        time = data['time']
        token = data['token']
        
        success = False
        status = 700
        
        if token in loggedInUsers:
            #print('here1')
            #this means the file is checked in
            if fileName in checkedInFiles:
            
                #this means it belongs to this user
                if checkedInFiles[fileName][0] == loggedInUser:
                    seconds2 = int(time)
                    endTime = datetime.now() + timedelta(seconds=seconds2)
                    newGrantTuple = (targetUser,fileName,accessRight,endTime)
                    listOfGrants.insert(0,newGrantTuple)
                    success = True
                else:
                    status = 702
        
        if success:
            # Similar response format given below can be
            # used for all the other functions
            response = {
                'status': 200,
                'message': 'Successfully granted access',
            }
        else:
            response = {
                'status': status,
                'message': 'Access denied to grant access',
            }
            print(f'listOfGrants{listOfGrants}')
        return jsonify(response)


class delete(Resource):
    """
        Expected response status codes:
        1) 200 - Successfully deleted the file
        2) 702 - Access denied deleting file
        3) 704 - Delete failed since file not found on the server
        4) 700 - Other failures
    """
    def post(self):
        data = request.get_json()
        token = data['token']
        user_id = data['user-id']
        fileName = data['fileName']
        success = False
        filePath = '/home/cs6238/Desktop/Project4/server/application/documents/' + fileName
        status = 700
        if token in loggedInUsers:
            
            if fileName in checkedInFiles:
                print('here2')
                #this means this user created the file
                if checkedInFiles[fileName][0] == user_id:
                    success = True
                    os.remove(filePath) 
                    checkedInFiles.pop(fileName,None)
                else:
                    status = 702
            else:
                status =704
        if success:
            # Similar response format given below can be
            # used for all the other functions
            response = {
                'status': 200,
                'message': 'Successfully deleted the file',
            }
        else:
            response = {
                'status': status,
                'message': 'Access denied deleting file',
            }
        return jsonify(response)


class logout(Resource):
    def post(self):
        """
            Expected response status codes:
            1) 200 - Successfully logged out
            2) 700 - Failed to log out
        """

        
        data = request.get_json()
        token = data['token']
            
        success = False
        if token in loggedInUsers:
            loggedInUsers.pop(token)
            success = True  
        
        if success:
            # Similar response format given below can be
            # used for all the other functions
            response = {
                'status': 200,
                'message': 'Successfully logged out',
            }
        else:
            response = {
                'status': 700,
                'message': 'Failed to log out',
            }
        return jsonify(response)



api.add_resource(welcome, '/')
api.add_resource(login, '/login')
api.add_resource(checkin, '/checkin')
api.add_resource(checkout, '/checkout')
api.add_resource(grant, '/grant')
api.add_resource(delete, '/delete')
api.add_resource(logout, '/logout')


def main():
    secure_shared_service.run(debug=True)


if __name__ == '__main__':
    main()
