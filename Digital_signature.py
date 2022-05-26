
from Crypto.Hash import SHA256
from tkinter import W
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
import PySimpleGUI as sg
import imageio
import TRNG

#---------------------------------------GUI-----------------------------------------------------#


while True: 
    layout = [[sg.VPush()],
    [sg.Button("Make signature",button_color=('white', 'green')), sg.Button("Check signature",button_color=('white', 'firebrick3'))],
    [sg.VPush()],
    ]

    window = sg.Window('Signature File', layout,element_justification='c',size=(820, 520))

    event, values = window.read()
    if event in (None, 'Exit'):
        break
    if event in ("Make signature"):
        window.close()
        layout = [
            [sg.Text('File to send                 '), sg.InputText(), sg.FileBrowse()
            ],
            [sg.Text('Source of randomness  '), sg.InputText(), sg.FileBrowse()
            ],
            [sg.Text('Place to save sign        '), sg.InputText(), sg.FolderBrowse()
            ],
            [sg.Text('Place to save key        '), sg.InputText(), sg.FolderBrowse()
            ],
            [sg.Output(size=(88, 20))],
            [sg.Submit(), sg.Cancel()]
        ]
        
        window = sg.Window('Signature File', layout,element_justification='c',size=(820, 520))
                                    # The Event Loop

        while True:                            
            event, values = window.read()
            # print(event, values) #debug
        
            if event in (None, 'Exit', 'Cancel'):
                window.close()
                break
            if event == 'Submit':
                #print(values[0],values[3])
                if values[0] and values[1] and values[2] and values[3]:
                    print(values[0])
                    print(values[1])
                    file_message = open(values[0],"rb") #open file to send
                    message = file_message.read()
                    message_sha3_256 = SHA256.new(message)

                    source_generator = imageio.imread(values[1])
                    file_generator = TRNG.getRandom(source_generator)

                    keys = RSA.generate(1024,file_generator.read)
                    private_key = keys.exportKey("PEM")
                    public_key = keys.publickey().exportKey("PEM")

                    file_for_key = open(values[2]+"/public_key.pem", 'wb')
                    file_for_key.write(public_key)
                    file_for_key.close()

                    print("\nSHA3-256 Hash: ", message_sha3_256.hexdigest())

                    print("\nprivate_key: ", private_key)
                    print("\npublic_key: ", public_key)

                    temp = PKCS1_v1_5.new(keys)

                    signature = temp.sign(message_sha3_256)

                    file_sign = open(values[3]+"/sign.txt", "wb")
                    file_sign.write(signature)
                        
                    print('Signature has been generated')

                    file_sign.close()
                    file_message.close()
                    
                else:
                    print('Please, choose everyone file.')  
          
    if event in ("Check signature"):
        window.close()
        layout = [
            [sg.Text('File to check       '), sg.InputText(), sg.FileBrowse()
            ],
            [sg.Text('Signature            '), sg.InputText(), sg.FileBrowse()
            ],
            [sg.Text('Public Key          '), sg.InputText(), sg.FileBrowse()
            ],
            [sg.Output(size=(88, 20))],
            [sg.Submit(), sg.Cancel()]
        ]

        window = sg.Window('Signature File', layout,element_justification='c',size=(820, 520))

        while True:                             # The Event Loop
            event, values = window.read()
            # print(event, values) #debug
            if event in (None, 'Exit', 'Cancel'):
                window.close()
                break
            if event == 'Submit':
                #print(values[0],values[3])
                if values[0] and values[1] and values[2]:
                    file_public_key = open(values[2],'rb')


                    public_key = RSA.importKey(file_public_key.read())
                    #print(public_key)

                    file_message = open(values[0],"rb") #open file to check
                    message = file_message.read()
                    message_sha3_256 = SHA256.new(message) #hash file to send

                    #wczytanie podpisu
                    file_sign = open(values[1], "rb")
                    sign = file_sign.read()



                    verification = PKCS1_v1_5.new(public_key)
                    if verification.verify(message_sha3_256, sign):
                        print("The signature is correct!")
                    else:
                        print("The signature is incorrect")
                else:
                    print('Please, choose everyone file')       
window.close()  