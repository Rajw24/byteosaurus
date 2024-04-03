import os
import time
import pyfiglet

def run_PE():
    file = input("Enter the path and name of the file : ")
    os.system("python Extract/PE_main.py {}".format(file))

def run_URL():
    os.system('python Extract/url_main.py')

def exit():
    os.system('exit')

def start():
    
    print(pyfiglet.figlet_format("Byte-O-Saurus"))
    print(" Welcome to malware detection system.\n")
    print(" 1. PE scanner")
    print(" 2. URL scanner")
    print(" 2. Exit\n")

    select = int(input("Enter your choice : "))

    if (select in [1,2,3]):

        if(select == 1):
            run_PE()
            choice = str(input("Do you want to search again? (y/n)"))
            if(choice not in ['Y','N','n','y']):
                print("Bad input\nExiting...")
                time.sleep(3)
                exit()
            else:
                if(choice == 'Y' or choice =='y'):
                    start()
                elif(choice == 'N' or choice =='n'):
                    exit()
         
        
        elif(select == 2):
            run_URL()
            choice = input("Do you want to search again? (y/n)")
            if(choice not in ['Y','N','n','y']):
                print("Bad input\nExiting...")
                time.sleep(3)
                exit()
            else:
                if(choice == 'Y' or choice =='y'):
                    start()
                elif(choice == 'N' or choice =='n'):
                    exit()

        else:
            exit()
    else:
        print("Bad input\nExiting...")
        time.sleep(3)
        exit()

start()