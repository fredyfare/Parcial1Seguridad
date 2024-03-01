import hashlib
from Crypto.Util.number import getPrime, inverse
import Crypto.Random

bits = 1024
e = 65537

pA = getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
qA = getPrime(bits, randfunc=Crypto.Random.get_random_bytes)

nA = pA * qA

phiA = (pA - 1) * (qA - 1)

dA = inverse(e, phiA)

with open("C:\\Users\\fredy\\Downloads\\NDA.pdf", "rb") as pdf:
    pdfBy = pdf.read()
    pdfHa = int.from_bytes(hashlib.sha256(pdfBy).digest(), "big")

sA = pow(pdfHa, dA, nA)

print(f"Hash A: {pdfHa}\n")

sBy = sA.to_bytes(
    (sA.bit_length() + 7) // 8, byteorder="big")

with open("C:\\Users\\fredy\\Downloads\\NDA.pdf", "ab") as pdf:
    pdf.write(sBy)


def r_lastBy(filename, num_bytes):
    with open(filename, "rb") as pdf:
        pdf.seek(-num_bytes, 2)
        return pdf.read(num_bytes)


sBy_pdf = r_lastBy(
    "C:\\Users\\fredy\\Downloads\\NDA.pdf", 256)
sInt_pdf = int.from_bytes(
    sBy_pdf, byteorder="big")

with open("C:\\Users\\fredy\\Downloads\\NDA.pdf", "rb") as pdf:
    pdfBy_AC = pdf.read()[:-256]
    pdfHa_AC = int.from_bytes(hashlib.sha256(pdfBy_AC).digest(), "big")

print(f"Hash AC: {pdfHa_AC}\n")

sVer_AC = pow(sInt_pdf, e, nA)

print(f"Firma verificada por la AC: {sVer_AC == pdfHa_AC}\n")

with open("C:\\Users\\fredy\\Downloads\\NDA.pdf", "wb") as pdf:
    pdf.write(pdfBy_AC)

pAC = getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
qAC = getPrime(bits, randfunc=Crypto.Random.get_random_bytes)

nAC = pAC * qAC

phiAC = (pAC - 1) * (qAC - 1)

dAC = inverse(e, phiAC)

sAC = pow(pdfHa_AC, dAC, nAC)

sAC_By = sAC.to_bytes(
    (sAC.bit_length() + 7) // 8, byteorder="big"
)
with open("C:\\Users\\fredy\\Downloads\\NDA.pdf", "ab") as pdf:
    pdf.write(sAC_By)

sBy_pdf_B = r_lastBy(
    "C:\\Users\\fredy\\Downloads\\NDA.pdf", 256)
sInt_pdf_B = int.from_bytes(
    sBy_pdf_B, byteorder="big"
)

with open("C:\\Users\\fredy\\Downloads\\NDA.pdf", "rb") as pdf:
    pdfBy_B = pdf.read()[:-256]
    pdfHa_B = int.from_bytes(
        hashlib.sha256(pdfBy_B).digest(), "big")

print(f"Hash de Bob: {pdfHa_B}\n")

pdf_hash_verif_bob = pow(sAC, e, nAC)

print(f"Firma verificada por Bob: {pdf_hash_verif_bob == pdfHa_AC}")
