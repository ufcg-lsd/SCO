import os
import zmq
import json
import time
import base64
import requests
from pwn import ELF
from pwn import context
from sys import argv
from os import system
from Crypto.Util.number import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import cmac, hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from consts import *

context.log_level = 'error'

def encrypt(key, plaintext):
    iv = os.urandom(12)

    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext 


def decrypt(key, ciphertext):
    iv = ciphertext[:12]
    tag = ciphertext[12:28]

    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    return decryptor.update(ciphertext[28:]) + decryptor.finalize()


def derive_key(shared_key, label):
    shared_key_le = shared_key[::-1]
    key_0_str = "00000000000000000000000000000000".decode("hex")

    c1 = cmac.CMAC(algorithms.AES(key_0_str), backend=default_backend())
    c1.update(shared_key_le)
    cmac_key0 = str(c1.finalize())

    derive_key_str = ("01" + label.encode("hex") + "008000").decode("hex")

    c2 = cmac.CMAC(algorithms.AES(cmac_key0), backend=default_backend())
    c2.update(derive_key_str)
    derived_key = c2.finalize()

    return derived_key


def send_msg0():
    public_numbers = public_key.public_numbers()
    key_base64_le = base64.b64encode(long_to_bytes(public_numbers.x)[::-1] + 
                                             long_to_bytes(public_numbers.y)[::-1])
    
    msg0_dict = {"message_type": MSG0, "payload": ("%s") % (key_base64_le)}
    communication_socket.send(json.dumps(msg0_dict))
    res = communication_socket.recv(2048)
    msg1_dict = json.loads(res)

    assert msg1_dict['message_type'] == MSG1
    return base64.b64decode(msg1_dict['payload'])


def process_msg1(msg1):
    global symmetric_key

    x = bytes_to_long(msg1[:32][::-1])
    y = bytes_to_long(msg1[32:64][::-1])
    gid = msg1[64:68][::-1]
    context = msg1[-4:]

    sp_public_key_le = msg1[:64]
    
    sp_public_key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key(default_backend())
    shared_key = private_key.exchange(ec.ECDH(), sp_public_key)

    derived_key_smk = derive_key(shared_key, "SMK")
    symmetric_key = derive_key(shared_key, "SK")

    public_numbers = public_key.public_numbers()
    public_key_le = long_to_bytes(public_numbers.x)[::-1] + long_to_bytes(public_numbers.y)[::-1]

    spid = "cb831ce194a3733369575ae6e6e9dbee".decode("hex")
    quote_type = "0000".decode("hex")[::-1]
    kdf_id = "0001".decode("hex")[::-1]

    public_keys_concat = public_key_le + sp_public_key_le
    sign_pk_concat_encoded = private_key.sign(public_keys_concat, ec.ECDSA(hashes.SHA256()))
    sign_pk_concat_decoded = utils.decode_dss_signature(sign_pk_concat_encoded)
    sign_pk_concat = long_to_bytes(sign_pk_concat_decoded[0])[::-1] + long_to_bytes(sign_pk_concat_decoded[1])[::-1]
    
    c = cmac.CMAC(algorithms.AES(derived_key_smk), backend=default_backend())
    c.update(public_key_le + spid + quote_type + kdf_id + sign_pk_concat)
    mac = c.finalize()

    response = requests.get(
        "https://test-as.sgx.trustedservices.intel.com:443/attestation/sgx/v2/sigrl/" + 
        gid.encode("hex"), cert='client.pem')

    assert response.status_code == 200
    
    sig_rl = base64.b64decode(response.content)
    sig_rl_size = format(len(sig_rl), "08x").decode("hex")

    msg2 = public_key_le + spid + quote_type + kdf_id + sign_pk_concat + mac + sig_rl_size + \
                sig_rl + context
    return msg2


def send_msg2(msg2):
    msg2_dict = {"message_type": MSG2, "payload": base64.b64encode(msg2)}
    communication_socket.send(json.dumps(msg2_dict))
    res = communication_socket.recv(2048)
    msg3_dict = json.loads(res)
    assert msg3_dict['message_type'] == MSG3
    return base64.b64decode(msg3_dict['payload'])


def process_msg3(msg3):
    mac = msg3[:16]
    sp_public_key_le = msg3[16:80]
    ps_sec_prop = msg3[80:336]
    quote = msg3[336:-4]
    context = msg3[-4:]
    
    aep_dict = {"isvEnclaveQuote": base64.b64encode(quote)}
    headers = {"Content-Type": "application/json"}
    response = requests.post(
        "https://test-as.sgx.trustedservices.intel.com:443/attestation/sgx/v2/report", 
        headers=headers, data=json.dumps(aep_dict), cert='client.pem')

    avr = json.loads(response.content)
    assert avr["isvEnclaveQuoteStatus"] == "OK"
    #print("Successfully verified QUOTE with IAS.")
    msg4 = "01".decode("hex") + context
    return msg4


def send_msg4(msg4):
    msg4_dict = {"message_type": MSG4, "payload": base64.b64encode(msg4)}
    communication_socket.send(json.dumps(msg4_dict))
    res = communication_socket.recv(2048)
    confirmation_dict = json.loads(res)
    assert confirmation_dict['message_type'] == CONFIRMATION
    return base64.b64decode(confirmation_dict['payload'])


def remote_attestation():
    msg1 = send_msg0()
    msg2 = process_msg1(msg1)
    msg3 = send_msg2(msg2)
    msg4 = process_msg3(msg3)
    confirmation = send_msg4(msg4)
    #print("Remote attestation process completed!")


def get_fas():
    get_fas_dict = {"message_type": DEF_INIT, "payload": ""}
    communication_socket.send(json.dumps(get_fas_dict))
    res = communication_socket.recv(2048)
    fas_dict = json.loads(res)
    assert fas_dict['message_type'] == DEF_FAS
    fas_dict  = json.loads(decrypt(symmetric_key, base64.b64decode(fas_dict['payload'])))
    return fas_dict


def create_dump_file(exec_file_name, exec_dump_file_name):
    cmd = "objdump -d "
    cmd += exec_file_name
    cmd += " > "
    cmd += exec_dump_file_name
    system(cmd)


def delete_file(file_name):
    cmd = "rm " + file_name
    system(cmd)

def get_return_type(file_name, function_name):
    #TODO: Fix the bug for when the function is called before its declaration
    with open(file_name) as f:
        lines = f.readlines()
    for line in lines:
        if function_name in line:
            return line[:line.index(function_name)].strip()

def compile_source(fas, source_c_file_name, function_name):
    tmp_executable_file_name = "bin_tmp"
    tmp_source_file_name = "source_tmp.c"
    
    with open(source_c_file_name) as f:
        source = f.read()

    for function in fas:
        if function in source:
            source = source.replace(function, fas[function])

    with open(tmp_source_file_name, "w") as f:
        f.write(source)
   
    system("gcc " +  tmp_source_file_name+ " -fPIC -fno-stack-protector -o " + tmp_executable_file_name)
    e = ELF(tmp_executable_file_name)
    f = e.functions[function_name]
    f_bytes = e.read(f.address, f.size)

    return_type = get_return_type(tmp_source_file_name, function_name)
    
    delete_file(tmp_executable_file_name)
    delete_file(tmp_source_file_name)
    
    return format(len(return_type), "02x").decode("hex") + return_type + f_bytes


def register_function(f_bytes):
    payload = encrypt(symmetric_key, f_bytes)
    register_function_dict = {"message_type": DEF_REGISTER, "payload": base64.b64encode(payload)}
    communication_socket.send(json.dumps(register_function_dict))
    res = communication_socket.recv(2048)
    msg_dict = json.loads(res)
    assert msg_dict['message_type'] == DEF_FID

    fid = decrypt(symmetric_key, base64.b64decode(msg_dict['payload']))
    return fid

def execute_function(fid, params):
    parsed_params = ""
    for p in params:
        if 'int' in p:
            parsed_params += format(int(p['int']), "08x").decode("hex")[::-1]
        elif 'str' in p:
            parsed_params += str(p['str']) + '\x00'

    payload = encrypt(symmetric_key, fid + parsed_params)
    execute_function_dict = {"message_type": DEF_EXECUTE, "payload": base64.b64encode(payload)}
    communication_socket.send(json.dumps(execute_function_dict))
    res = communication_socket.recv(2048)
    msg_dict = json.loads(res)
    assert msg_dict['message_type'] == DEF_RESULT

    result_le = decrypt(symmetric_key, base64.b64decode(msg_dict['payload']))
    result = ""
    for i in xrange(len(result_le) / 8):
        result += result_le[8 * i : 8 * i + 8][::-1]

    if len(result_le) % 8 != 0:
        result += result_le[8 * (len(result_le) / 8): ][::-1]
    
    return result

def execute_terminate():
    payload = ""
    terminate_dict = {"message_type":TERMINATE_MESSAGE, "payload":payload}
    communication_socket.send(json.dumps(terminate_dict))
    
if __name__ == "__main__":
    if len(argv) != 2:
        usage()

    with open(argv[1]) as conf_file:
        conf = json.load(conf_file)
    
    source_c_file_name = conf['file']
    f_name = conf['function']

    private_key = ec.generate_private_key(ec.SECP256R1, default_backend())
    public_key = private_key.public_key()
    symmetric_key = None

    communication_context = zmq.Context.instance()
    communication_socket = communication_context.socket(zmq.REQ)
    communication_socket.connect("tcp://localhost:8888")
    
    start = time.time()
    remote_attestation()
    fas = get_fas()
    function = compile_source(fas, source_c_file_name, f_name)
    fid = register_function(function)
    result = execute_function(fid, conf['params'])
    end = time.time()

    print("==== Result =====")
    print("number: " + str(bytes_to_long(result)))
    print("hex: " + result.encode("hex"))
    print("str: " + result)

    start = int(round(start*10**6))
    end = int(round(end*10**6))
    print "dynsgx_first,"+str(end-start)

    start = time.time()
    result = execute_function(fid, conf['params'])
    end = time.time()

    start = int(round(start*10**6))
    end = int(round(end*10**6))
    print "dynsgx_second,"+str(end-start)

    execute_terminate()

    communication_socket.close()
