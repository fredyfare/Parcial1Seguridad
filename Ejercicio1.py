import Crypto.Util.number
import hashlib

# Mensaje original lorem
m = "Lorem ipsum dolor sit amet, consectetur adipiscing elit Proin vel aliquet libero. Vestibulum sollicitudin nunc risus, sit amet aliquet arcu commodo in. Sed quis urna laoreet, egestas magna vitae, sagittis magna. Fusce ut lorem ornare, feugiat mauris in, efficitur ipsum. Duis efficitur efficitur leo, quis gravida est malesuada in. Phasellus iaculis metus non neque tempus venenatis. Etiam euismod nunc in erat elementum tristique. Quisque luctus pulvinar nisl. Nulla purus justo, viverra eu laoreet a, gravida et orci. In diam lectus, egestas sit amet lacinia vel, accumsan sed lorem. Donec vel accumsan ex, a molestie ante. Nunc non imperdiet nisi. Maecenas et aliquet tellus. Pellentesque laoreet erat accumsan nulla pharetra, vel vestibulum nibh efficitur. Nam eleifend sem dui, eu tincidunt diam elementum in. Vestibulum ut euismod magna, eu hendrerit turpis. Proin in nunc rhoncus, finibus tortor at, tincidunt metus. Morbi sed metus dolor. Morbi tempor posuere massa ac volutpat. In molestie viverra nisl, vitae pharetra metus pharetra id sed."
print(f"Mensaje original: {m} \n\nCaracteres: {len(m)} caracteres \n")
m_bytes = bytes(m, 'utf-8')
# Aplicamos hash al mensaje
m_hash = hashlib.sha256(m_bytes).hexdigest()
print(f"Hash de m: {m_hash}\n")

# Se divide el mensaje original
m_divided = [m[i:i+128] for i in range(0, len(m), 128)]

bits = 1024

# Se obtienen los primos de Alice (A) y Bob (B)
qA = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
# print(f"qA: {qA}\n")
pA = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
# print(f"pA: {pA}\n")

qB = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
# print(f"qB: {qB}\n")
pB = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
# print(f"pB: {pB}\n")

# Primeras partes de las llaves públicas
nA = qA*qB
print(f"Primera parte llave publica A (nA): {nA}\n")
nB = pA*pB
print(f"Primera parte llave publica B (nB): {nB}\n")

# Segundas partes de las llaves públicas
phiA = (qA-1)*(qB-1)
print(f"Segunda parte llave publica A (phiA): {phiA}\n")
phiB = (pA-1)*(pB-1)
print(f"Segunda parte llave publica B (phiB): {phiB}\n")

e = 65537

# Llaves privadas de A y B
dA = Crypto.Util.number.inverse(e, phiA)
print(f"Llave privada A (dA): {dA}\n")
dB = Crypto.Util.number.inverse(e, phiB)
print(f"Llave privada B (dB): {dB}\n")

m_divided_encryptions = []

for j in m_divided:
    w = int.from_bytes(str(j).encode('utf-8'), byteorder='big')
    c = pow(w, e, nB)
    print(f"Mensaje encriptado de fragmento - {j}: {c}\n")
    m_divided_encryptions.append(c)

m_divided_decryptions = []

for c in m_divided_encryptions:
    w = pow(c, dB, nB)
    decrypted_msg_bytes = w.to_bytes(
        (w.bit_length() + 7) // 8, byteorder='big')
    m_divided_decryptions.append(decrypted_msg_bytes)

m_joined = b''.join(m_divided_decryptions).decode('utf-8')

m_joined_bits = bytes(m_joined, 'utf-8')
m_joined_hash = hashlib.sha256(m_joined_bits).hexdigest()


print(f"Mensaje desencriptado y junto: {m_joined}\n\nCaracteres: {len(m_joined)} caracteres\n")

print(f"Hash de m: {m_hash} \n\nHash de m_joined: {m_joined_hash}\n")
print(f"Hash de m es igual a hash de m_joined juntos: {
      m_hash == m_joined_hash}")
