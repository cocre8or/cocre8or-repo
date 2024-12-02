import os, re
import shutil
import subprocess
import sys

sourcepath = "/home/cs6238/Downloads"
destReqpath = "/home/cs6238/Desktop/Project4"
destServerpath = "/home/cs6238/Desktop/Project4/server/application"
destClient1path = "/home/cs6238/Desktop/Project4/client1"
destClient2path = "/home/cs6238/Desktop/Project4/client2"
dirList = os.listdir(sourcepath)

success = False

# delete old student file from client1
try:
    for item in os.listdir(destClient1path):
	    isAFile = os.path.join(destClient1path, item)
	    if not item.endswith(".py") and isAFile:
		    os.remove(os.path.join(destClient1path, item))
except:
    print('No client1 file found')



# delete old student file from client2
try:
    for item in os.listdir(destClient2path):
        isAFile = os.path.join(destClient2path, item)
        if not item.endswith(".py") and isAFile:
	        os.remove(os.path.join(destClient2path, item))
except:
    print('No client2 file found')


try:
	for f in dirList:
		if re.match('requirements',f):
			old = os.path.join(sourcepath, f)
			newp = os.path.join(sourcepath, 'requirements.txt')
			os.rename(old, newp)
			shutil.copyfile(newp, os.path.join(destReqpath,'requirements.txt'))
		if re.match('client',f):
			old = os.path.join(sourcepath, f)
			newp = os.path.join(sourcepath, 'client.py')
			os.rename(old, newp)
			shutil.copyfile(newp, os.path.join(destClient1path,'client.py'))
			shutil.copyfile(newp, os.path.join(destClient2path,'client.py'))
		if re.match('server',f):
			old = os.path.join(sourcepath, f)
			newp = os.path.join(sourcepath, 'server.py')
			os.rename(old, newp)
			shutil.copyfile(newp, os.path.join(destServerpath,'server.py'))
	success = True
except:
	print('Failed')
if success == True:
	print("Completed filename changes and moved")
	os.remove(os.path.join(sourcepath, 'requirements.txt'))
	os.remove(os.path.join(sourcepath, 'client.py'))
	os.remove(os.path.join(sourcepath, 'server.py'))
	print("All complete")
