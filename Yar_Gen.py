from io import BytesIO
import sys
import time
from tkinter import *
from urllib.request import urlopen
from PIL import Image, ImageTk
from datetime import date
import sys
import re
import string
from string import ascii_lowercase
import pefile
import tempfile
  

from tkinter import filedialog

# to Compress Image Icon
import base64, zlib

import argparse
import math
 # GUI part
def clock():
    date=time.strftime('%d/%m/%Y')
    curtime=time.strftime('%H:%M:%S')
    datetimelabel.config(text=f'  Date : {date}\nTime : {curtime}')
    datetimelabel.after(1000,clock)
count=0
text=''
def slider():
    global text,count
    if count==len(s):
        count=0
        text=''
    text=text+s[count] #s
    sliderlabel.config(text=text)
    count+=1
    sliderlabel.after(200,slider)
def shannon_entropy(data):
    # 256 different possible values
    possible = dict(((chr(x), 0) for x in range(0, 256)))

    for byte in data:
        possible[chr(byte)] +=1

    data_len = len(data)
    entropy = 0.0

    # compute
    for i in possible:
        if possible[i] == 0:
            continue

        p = float(possible[i] / data_len)
        entropy -= p * math.log(p, 2)
    return entropy

# browsed file
filename = ''

# nop inside an exe
empty_Space = 0



# icon image as base64
ICON = zlib.decompress(base64.b64decode('eJxjYGAEQgEBBiDJwZDBy'
    'sAgxsDAoAHEQCEGBQaIOAg4sDIgACMUj4JRMApGwQgF/ykEAFXxQRc='))

# creating the icon image 
_, ICON_PATH = tempfile.mkstemp()
with open(ICON_PATH, 'wb') as icon_file:
    icon_file.write(ICON)

def strings(filename, min=8):
    with open(filename, errors="ignore") as file:
        result = ""
        for character in file.read():
            if character in string.printable:
                result += character
                continue
            if len(result) >= min:
                yield result
            result = ""
        if len(result) >= min:
            yield result
# Python program to find the SHA-1 message digest of a file

# importing the hashlib module
import hashlib

def hash_file(filename):
   """"This function returns the SHA-1 hash
   of the file passed into it"""

   # make a hash object
   h = hashlib.sha1()

   # open file for reading in binary mode
   with open(filename,'rb') as file:

       # loop till the end of the file
       chunk = 0
       while chunk != b'':
           # read only 1024 bytes at a time
           chunk = file.read(1024)
           h.update(chunk)

   # return the hex representation of digest
   return h.hexdigest()




def getMD5(filename): 
  
    # initialize hash 
    md5 = hashlib.md5() 
  
    # open file for reading in binary mode 
    with open(filename,'rb') as file: 
  
        # loop till the end of the file 
        chunk = 0
        while chunk != b'': 
            # read only 1024 bytes at a time 
            chunk = file.read(1024) 
            md5.update(chunk) 
  
    # return md5 digest 
    return md5.hexdigest()


def sha256_hash(filename):
   h  = hashlib.sha256()
   with open(filename,'rb') as file:
       chunk = 0
       while chunk != b'':
           chunk = file.read(1024)
           h.update(chunk)
   return h.hexdigest()


  
# function for opening the file explorer window
def browseFiles():
    global filename

    # select file types on browser
    filename = filedialog.askopenfilename(
                                          title = "Select a File",
                                          filetypes = (("EXE files",".exe"),
                                                       ("DLL files",".dll"),                                                       
                                                       ("all files","*.*")))
    
      
    # change label contents
    label1.configure(text="File Opened: "+filename)

      
    # activate cave button
    if filename != "":
        button_Caves.configure(state="normal")
    

# function to find caves
def caves():
 global filename
 pe = pefile.PE(filename)
 exe = filename.split("/")[-1].split(".")[0]
 with open(filename, 'rb') as f:
        data = f.read()
        f.close
 message = hash_file(filename)
 print(exe)
 with open(exe.replace('-','').replace('/ ','').replace(' ','')+'.yar', 'w+') as file:
    file.write("import \"hash\""+'\n'
    #   +"import \"pe\""+'\n'
    #   +"import \"math\""+'\n'
      +"rule "+exe.replace('-','').replace('/ ','').replace(' ','')+'\n'
      +"{\n"+
      ' meta:\n'+
      '   description=\"Rule to find '+exe+'\"\n'+
      '   author = \"Yara Team\"\n'+
      '   date = '+date.today().strftime("%d%m%Y")+'\n\n\n'
      ' strings:\n'
      '  $a = {4d 5a} \n')
   
    counter1 = 0
    counter2  = 0
    counter3  = 0
    counter4  = 0

    
    for string_line in strings(filename):
                try:
                    if "This filename cannot be run in DOS mode" not in string_line:
                     if "MinGW" not in string_line:
                        if "_" not in string_line:
                            if "idata" not in string_line:
                                if "rsrc" not in string_line:
                                    if "CRT" not in string_line:
                                        if "rdata" not in string_line:
                                            if "requestedExecutionLevel" not in string_line:
                                                if "rtc" not in string_line:
                                                    if string_line.replace("\n","").replace(" ","") != "":
                                                        if string_line.isascii():
                                                            if "\n" not in string_line:
                                                                if len(string_line) > 150:
                                                                    string_line = string_line[0:150]
                                                                    file.write('  $'+ascii_lowercase[counter1]+ascii_lowercase[counter2]+ascii_lowercase[counter3]+ascii_lowercase[counter4]+' = \"'+string_line.replace("\"","\\\"").replace("\\","\\\\")+'\" \n')
                                                                    counter1 = counter1 +1
                                                                else:
                                                                    file.write('  $'+ascii_lowercase[counter1]+ascii_lowercase[counter2]+ascii_lowercase[counter3]+ascii_lowercase[counter4]+' = \"'+string_line.replace("\"","\\\"").replace("\\","\\\\")+'\" \n')
                                                                    counter1 = counter1 +1
                except:
                    try:
                        counter1 = 0
                        counter2 = counter2 + 1
                    except:
                        try:
                            counter2 = 0
                            counter3 = counter3 + 1
                        except:
                            try:
                                counter3 = 0
                                counter4 = counter4 + 1
                            except:
                                counter4 = 0


    file.write('  \n\n\n'
          '  condition:\n'
          '  (hash.md5(0,filesize)=="'+getMD5(filename)+
          '\") and  \n  (hash.sha1(0,filesize)==\"'+message+
          '\") and \n  (hash.sha256(0,filesize)=="'+sha256_hash(filename)+
          '\") \n   or ($a at 0) and any of them \n'
          "   and (uint32(uint32(0x3C)) == 0x00004550) \n"+
          "   and (pe.number_of_sections == "+str(pe.FILE_HEADER.NumberOfSections)+")\n"
          "   and (pe.timestamp == "+str(pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split('[')[0])+")\n"
          "   "+"")
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
          for imp in entry.imports:
            file.write ('   and pe.imports("'+str(entry.dll).replace("b","").replace("'","").replace("_","")+'", "'+str(imp.name).replace("b'_","").replace("'","")+'")\n')

    if hex(pe.OPTIONAL_HEADER.Magic) == '0x10b':
            file.write("   and (pe.machine == pe.MACHINE_I386)\n")
    elif hex(pe.OPTIONAL_HEADER.Magic) == '0x20b':
            file.write("   and (pe.machine == pe.MACHINE_AMD64)\n")
    counter = 0
    counter = 0
    for section in pe.sections:
        file.write('   and pe.sections['+str(counter)+'].name == "'+str(section.Name.decode()).replace("\0","")+'" \n')
        counter = counter + 1

    string_version_info = {}
    
    try:
        for fileinfo in pe.FileInfo[0]:
                if fileinfo.Key.decode() == 'StringFileInfo':
                        for st in fileinfo.StringTable:
                                for entry in st.entries.items():
                                        string_version_info[entry[0].decode()] = entry[1].decode()

        for i in string_version_info:
            file.write('   and pe.version_info["'+i + '"] contains "' + string_version_info[i]+ '" \n')
    except:
        pass
        
    if data:
            entropy = shannon_entropy(data)
            file.write("   and math.entropy(0, filesize) >= "+str(entropy).split(".")[0]+".0 \n")
    file.write('\n\n\n'+
          '}'
          )
    label1.configure(text="DONE: "+ exe.replace('-','').replace('/ ','').replace(' ','') + ".yar created")

Window = Tk()
Window.title("project yara")
Window.geometry('1280x700+0+0')

url2="https://i.postimg.cc/Y9qtcWhf/search.png"
url3="https://i.postimg.cc/DZpFXQSq/cyber-security-3400657-1920.jpg"
url = "https://i.postimg.cc/mgxMTXLZ/file.png"
u = urlopen(url3)
raw_data = u.read()
u.close()
im = Image.open(BytesIO(raw_data))
image = ImageTk.PhotoImage(im)
label = Label(Window,image=image)
label.place(x=0,y=0)
datetimelabel=Label(Window,
                    font=('times new roman',18,'bold'))
datetimelabel.place(x=5,y=5)
clock()
s='Yara Signature Optimizer'
sliderlabel=Label(Window,text=s,
                  font=('arial',28,'italic bold'),
                  width=28)
sliderlabel.place(x=580,y=50)
slider()
file_frame=Frame(Window)
file_frame.place(x=700,y=250)
u1 = urlopen(url2)
raw_data1 = u1.read()
u1.close()

im1 = Image.open(BytesIO(raw_data1))
image1 = ImageTk.PhotoImage(im1)
label1 = Label(file_frame,image=image1,text = "Browse your EXE/DLL file",
                            compound=LEFT,
                            width=500,font=('times new roman',20),
                            fg = "black")
label1.grid(column=1,row=0,pady=5)
u2 = urlopen(url)
raw_data2 = u2.read()
u2.close()
im2 = Image.open(BytesIO(raw_data1))
image2 = ImageTk.PhotoImage(im1)
label2 = Button(file_frame,image=image2,text = "Upload File",
                  width=300,
                  fg='white',
                  bg='blue',
                  compound=LEFT,
                  activebackground='blue',
                  activeforeground='white',
                  cursor='hand2',
                  font=('times new roman',20),
                  command=browseFiles)

label2.grid(column=1,row=1,pady=10)
button_Caves = Button(file_frame,
                     text = "Generate  yara rules",
                     width=17,
                     state = DISABLED,
                     cursor='hand2',
                     font=('times new roman',20),
                     fg='black',
                     command=caves)

                     
button_Caves.grid(column=1, row=2,pady=10)
button_Exit = Button(Window,
                     text = "Exit",
                     width = 6,
                     height=1,
                     cursor='hand2',
                     font=('times new roman',20),
                     fg = "black",
                     command = sys.exit)
button_Exit.place(x=900,y=850)
Window.mainloop()
