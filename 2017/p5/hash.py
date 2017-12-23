#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hashlib
import sys
from random import randint
import time
import sys

"""
#Funcion que devuelve una cadena aleatoria de nBits binario
#devuelve la cadena en entero. Por ejemplo 3 bits, 0..a 7
"""
def randomBits(nBits):
	bits = ""
	for x in range(0,int(nBits)):
		bits = bits+""+str(randint(0,1))
	bits = int(bits,base=2)
	return bits

#Funcion que devuelve n numeros aleatorios
def random_with_N_digits(n):
	n = int(n)
	range_start = 10**(n-1)
	range_end = (10**n)-1
	return randint(range_start, range_end)


#Funcion que convierte una cadena ascii a binario
def asciiToBinary(chain):
	chain=bin(int(str(chain),16))
	return chain

#se le pasan string
def sumBinary(a,b):
	a = int(a)
	b = int(b)
	return (str(asciiToBinary(a+b)))

def hashing(msg, bits):
	idM = str(bits)[2:]+""+msg #quitamos el 0b
	idM = str(idM).encode('utf8')
	return (str(hashlib.sha256(idM).hexdigest()))	




def run(message,nbits):
	contador=0
	strZero="0"*nbits
	"""
	Generamos el numero aleatorio en binario
	"""
	x = randomBits(nbits)
	xBin = bin(x)

	"""
	Creamos el id concatenando la cadena de bits y el mensaje.
	Aplicamos hash, todo ello con el metodo hashing
	"""
	#idM = str(xBin)+""+message
	hashM = hashing(message,xBin)
	#idM  0b10101010holamundo


	hashMBin=bin(int(hashM, 16)) #hexadecimal a binario
	chainHashBin = hashMBin
	
	chainSumX=xBin

	sumHash=x
	
	#seguimos sumando uno a la cadena de bits mientras los primeros nBits sean distintos de 0
	while((str(chainHashBin[len(chainHashBin)-nbits:])!=str(strZero))):
		contador+=1
		#print("\nNumero aleatorio binario en decimal"+str(int(xBin,base=2)))
		sumHash=randomBits(nbits)
		#print("\nSuma"+str(sumHash))
		chainBin = bin(sumHash)
		chainSumX = chainBin+""+chainSumX

		
		#procedemos a concatenar y aplicar la funciona hash
		chainHashBin=hashing(message,chainSumX)

		chainHashBin=bin(int(chainHashBin,16))
		
	print("\nId: "+chainSumX+message)
	print("\nCadena bits: "+str(bin(sumHash)))
	print("\nIteracion: "+str(contador))
	print("\nHash: "+str(chainHashBin))

run("holamundo",int(sys.argv[1]))