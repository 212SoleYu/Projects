from gmssl import func
from gmssl import sm3
import my_sm3
import datetime
## 为了完成对sm3的长度扩展攻击，主要完成以下三个步骤：
## 1.随机生成一个秘密secret，并计算其哈希值old_hash
## 2.我们对old_hash进行加密来得到我们伪造的哈希值forged_hash.
## 3.我们人工的填充一个值m‘，其中m‘ = secret + padding + add，并且计算m’的哈希值new_hash,验证new_hash和forged_hash是否相等，若相等则说明攻击成功

def padding(secret,add):
    ## 将字符串形式的secret填充为满足分组长度并且在后面添加上add,最后再返回字符串
    secret = func.bytes_to_list(bytes(secret, encoding='utf-8'))
    secret_len = len(secret)
    rest = secret_len % 64
    secret.append(0x80)
    rest+=1
    if(rest<=56):
        for i in range(56-rest):
            secret.append(0x00)
    elif (rest>56):
        for i in range(119-rest):
            secret.append(0x00)
    for i in range(8):
        secret.append(((secret_len >> (7-i)*8) & 0xff) * 8)
    secret = func.list_to_bytes(secret)
    secret += bytes(add.encode())
    return secret

def lengthExtend(old_hash, add, length):
    # 进行长度扩展攻击，已知old_hash,原消息的长度，以及想要添加的字段add
    # 先将old_hash分块，分为8个向量
    V = []
    for i in range(8):
        V.append(int(old_hash[i*8:i*8+8],16))
    # 然后伪造消息，长度为length的任意消息a和填充内容以及要添加的内容add
    message = ""
    if length > 64:
        for i in range(0, int(length / 64) * 64):
            message += 'a'
    for i in range(0, length % 64):
        message += 'a'

    ## 填充message
    message = padding(message, "")
    message = func.bytes_to_list(message)
    add = func.bytes_to_list(bytes(add, encoding='utf-8'))
    message.extend(add)
    print("The forged message:", func.list_to_bytes(message).decode('utf-8','ignore'))
    ans = my_sm3.sm3_hash(message, V)
    return ans

secret = "length extend attack "
today=datetime.date.today()
secret += str(today)
add = "add"
old_hash = sm3.sm3_hash(func.bytes_to_list(bytes(secret,encoding='utf-8')))
print("The secret message:", secret)
print("The old hash:", old_hash)
print("The message to be added:",add)
forged_hash = lengthExtend(old_hash,add,len(secret))
print("The forged hash:",forged_hash)
forged_message = padding(secret,add)
print("The padding message:",(forged_message).decode('utf-8','ignore'))
new_hash = sm3.sm3_hash(func.bytes_to_list(forged_message))
print("The new hash:", new_hash)
print("Checking...")
if(new_hash == forged_hash):
    print("Success!")
else :
    print("Failed!")
