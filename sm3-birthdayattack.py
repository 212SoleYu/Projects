from gmssl import sm3
from gmssl import func
import random

def hashcheck(list):
    for i in range(len(list)):
        bit_message = str(list[i])
        hash = sm3.sm3_hash(func.bytes_to_list(bytes(bit_message, encoding='utf-8')))
        print(hash)

def birthdayAttack(listlen,round,hashlen):
    print("Collision in first",hashlen,"bytes:")
    randomlist = []
    dictA = dict()#用于存放一对多的数据
    for i in range(pow(2,listlen)):
        r = random.randint(0, pow(2,64))
        if r not in randomlist:
            randomlist.append(r)
    for i in range(pow(2,round)):
        message = str(randomlist[i])
        bit_message = str(randomlist[i])
        hash = sm3.sm3_hash(func.bytes_to_list(bytes(bit_message,encoding = 'utf-8')))
        hash = hash[0:hashlen]#提取前n位进行碰撞
        if hash not in dictA:
            dictA[hash] = []
            dictA[hash].append(message)
        else:
            dictA[hash].append(message)
    flag = 0
    for key,list in dictA.items():
        if(len(list)>=2):
            flag=1
            print("Hash:", key)
            print("Collision value:",list)
            hashcheck(list)
    if flag == 0:
        print("No Collision")

birthdayAttack(13,12,6)


