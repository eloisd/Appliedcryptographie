##############################
##   0 : INTRO
##   Les formats de chaînes en Python
#############################

0xF
#=> 15

## Une cléen hexa clé
K=0x6e213189314cd8d2cdfd86c944da1467
K
#=> 146387430040258906480581650393585030247

bin(K)
#=> '0b1101110001000010011000110001001001100010100110011011000110100101100110111111101100001101100100101000100110110100001010001100111'

## Attention aux types d'objets en Python
import base64

n=123456789987654321
base64.b64encode(hex(n).encode('utf8'))  ## A essayer

n_dec=str(n)
n_bin=bin(n)
n_hex=hex(n)

n_dec_e=n_dec.encode('utf8')
n_bin_e=n_bin.encode('utf8')
n_hex_e=n_hex.encode('utf8')

n_dec_b64= base64.b64encode(n_dec_e)
n_bin_b64= base64.b64encode(n_bin_e)
n_hex_b64= base64.b64encode(n_hex_e)

## On retrouve l'entier 
int(base64.b64decode(n_dec_b64))

###### Installation à partir du cmd windows
###### py -m pip install backports.pbkdf2
###### py -m pip install pyaes
###### py -m pip install pbkdf2

######################
##
## d'autes petits essais à effectuer sur les chaîne de caractères
##
######################

import os, binascii
from backports.pbkdf2 import pbkdf2_hmac


'aze'[1]
#=> 'z'

'aze'.encode('utf8')
#=> b'aze'

'aze'.encode('utf8')[0]
#=> 97

'aze'.encode('utf8')[1]
#=> 122

'aze'.encode('utf8')[2]
#=> 101

binascii.hexlify('aze'.encode('utf-8'))
#=> b'617a65'

##  Remarquer
hex(97)
#=> '0x61'

hex(122)
#=> '0x7a'

hex(101)
#=> '0x65'

A=b'abc'
A
#=> b'abc'

A[0]
#=> 97

A
#=> b'abc'

binascii.hexlify(A)
#=> b'616263'

###########################################
##
##   EXERCICE 1 : 
##
##   Partie 1
##   Le salage des mots de passe
## 
##   Peut servir pour le stockage des mots de passe, Attentions aux différents types de variables employés sous Python !
##
###########################################

## Commençons avec le sel

salt = binascii.unhexlify("aaef2d3f4d77ac66e9c5a6c3d8f921d1".encode('utf-8'))    ##  OK
salt
#=> b'\xaa\xef-?Mw\xacf\xe9\xc5\xa6\xc3\xd8\xf9!\xd1'

binascii.hexlify(salt)
#=> b'aaef2d3f4d77ac66e9c5a6c3d8f921d1'

"aaef2d3f4d77ac66e9c5a6c3d8f921d1".encode('utf-8')
#=> b'aaef2d3f4d77ac66e9c5a6c3d8f921d1'

binascii.hexlify(salt).decode('utf8')
#=> 'aaef2d3f4d77ac66e9c5a6c3d8f921d1'

shexa=binascii.hexlify(salt)
shexa
#=> b'aaef2d3f4d77ac66e9c5a6c3d8f921d1'

int(shexa,base=16)
#=> 227210635956406946994914048492206367185

hex(int(shexa,base=16))
#=> '0xaaef2d3f4d77ac66e9c5a6c3d8f921d1'

### Continuons avec le mot de passe

passwd = "p@$Sw0rD~1".encode("utf8")    
passwd
#=> b'p@$Sw0rD~1'

key = pbkdf2_hmac("sha256", passwd, salt, 50000, 32)     ## OK, nombre d'itérations et longueur de clé
key
#=> b'R\xc5\xef\xa1np"\x85\x90Q\xb1\xde\xc2\x8b\xc6]\x96\x96\xa3\x00]\x0f\x97\xe5\x06\xc4(C\xbc;\xdb\xc0'


Kb=binascii.hexlify(key)
#=> b'52c5efa16e7022859051b1dec28bc65d9696a3005d0f97e506c42843bc3bdbc0'

## On peut aussi écrire :
int(Kb,base=16)

##############################"
#
# Partie 2 : Derive a 256-bit AES encryption key from the password, en Python
#
############################

import pyaes, pbkdf2, binascii, os, secrets

password = "s3cr3t*c0d3"
passwordSalt = os.urandom(16)
passwordSalt    #####   Va changer à chaque session
#=>  b'\xa7\x15(\x8e6\xc7k\xa3\xf0(\xb6\x9a\xb7xp\xa4'

key = pbkdf2.PBKDF2(password, passwordSalt).read(32)
key
#=> b"p\xed\xfc\x18\xacU'S\xbc:\xe0B\xfa\teU`-2\x05\xf0\x0c\x88\xc3\xe4E\x0e\xc6\xe1\xf0\xb7o"

essaiK=pbkdf2.PBKDF2(password, passwordSalt)
#=> <pbkdf2.PBKDF2 object at 0x0000027F9D140640>


binascii.hexlify(key)

iv = secrets.randbits(256)
iv      ### Va changer à chaque fois !!!
#=> 63106492188819967556107174752636020071058674954912363858650833485958455660518


plaintext = "Text for encryption"    ## Cet exemple est dans le cours
aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
ciphertext = aes.encrypt(plaintext)

### Attention pour déchiffrer, il faut recréer un objet aes !!!
aes.decrypt(ciphertext)

aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
aes.decrypt(ciphertext)


###################################
##
##  EXERCICE 2 : Déchifrage d'un texte, en Python
##
##################################


iv0=6*(10**76)
n=7777888899000011112233334444551234567

hex(n)
#> '0x5d9f787a42439232df1a3c56df6e407'
key0=binascii.unhexlify(b'05d9f787a42439232df1a3c56df6e407')
## key0 = b'\x05\xd9\xf7\x87\xa4$9#-\xf1\xa3\xc5m\xf6\xe4\x07'

aes = pyaes.AESModeOfOperationCTR(key0, pyaes.Counter(iv0))
Texte1="Bonjour à vous tous"
Texte2="Bienvenue a notre TD."

ciphertext1 = aes.encrypt(Texte1)    #  b'\xd0\xbdT\x81_\xfb\xc4\xef\x92\xe6^\x12\xb7\xea\xc4\xff\xfd\x1f\xe9'
ciphertext2 = aes.encrypt(Texte2)    #  b';\x98\xd0m\x8d\x9f\xc5\xf3\x02\x99&\t\xfe=\xf6\n\x06\xb6Z\x1f\xf4'

ciphertext1 = b'\xd0\xbdT\x81_\xfb\xc4\xef\x92\xe6^\x12\xb7\xea\xc4\xff\xfd\x1f\xe9'
ciphertext2 = b';\x98\xd0m\x8d\x9f\xc5\xf3\x02\x99&\t\xfe=\xf6\n\x06\xb6Z\x1f\xf4'

aes = pyaes.AESModeOfOperationCTR(key0, pyaes.Counter(iv0))
aes.decrypt(ciphertext1)
aes.decrypt(ciphertext2)



###########################################
##
####  EXERCICE 3 : hashage, avec SHA256
##
###########################################

import hashlib as hs
import random

## Constater  qu'une fonction de hashage mélange bien les bits ...
## Commencer par un calcul élémentaire, constater qu'on peut hasher un texte long, vérifier la taille d'un hash

Texte="Ecrire n'impporte quoi, ..."
Hh=int(hs.sha256(Texte.encode('utf-8')).hexdigest(),base=16)   ## Si vous avez le temps, examinez toutes les étapes intermédiaires

## Maintenant, vous changez une virgule ou un caratère, et examinez "à l'oeil" les changements

Texte2="Ecrire n'impporte quoi; ..."
Hh2=int(hs.sha256(Texte.encode('utf-8')).hexdigest(),base=16)

LesBitesDifferents=bin(Hh1)^bin(Hh2)
LesBitesDifferents                      ## En principe, environ la moitié




############################################
##
## EXERCICE 4 : utilisation de l'AES avec openssl  
##
############################################

##  Openssl à installer sur son PC
##  Vérifier le répertoire de travail où sont positionnés les fichiers


##  la fonction de chifrement AES, avoir réflexe de regarder la doc

##
##   On utilise l'AES en mode dit CTR (avec compteur en plus de la clé
##   La clé n'est pas entrée directement, mais un mot de passe à la place
##   le mot de passe est déduit de la clé avec la fonction de dérivation de clé pbkdf2
##
##   Créez vous des ptits fichiers .txt : TexteBasique.txt, TexteBasiqueRaccourci consiste à supprimer quelques caractères à la fin
##   et aussi un petit fichier au format word (vous pouvez y mettre des couleurs, changer les fontes, etc..) : TestWord.docx
##

#openssl enc -pbkdf2 -aes-256-ctr -iv 0123456789 -k 0123456789 -in TexteBasique.txt -out TexteBasique.enc            ## Chiffrage

#openssl enc -d -pbkdf2 -aes-256-ctr -iv 0123456789 -k 0123456789 -in TexteBasique.enc -out TexteBasiqueDec1.txt     ## Déchiffrage

##  Avec Word

#openssl enc -pbkdf2 -aes-256-ctr -iv 0123456789 -k 0123456789 -in TestWord.docx -out TestWord.enc

#openssl enc -d -pbkdf2 -aes-256-ctr -iv 0123456789 -k 0123456789 -in TestWord.enc -out TestWordDec1.docx

## Je fais un test sans l'option -pbkdf2

#openssl enc -aes-256-ctr -iv 0123456789 -k 0123456789 -in TexteBasique.txt -out TexteBasique2.enc

#openssl enc -d -aes-256-ctr -iv 0123456789 -k 0123456789 -in TexteBasique2.enc -out TexteBasiqueDec2.txt

## J'utilise la mauvaise option de déchiffrement

#openssl enc -d -aes-256-ctr -iv 0123456789 -k 0123456789 -in TexteBasique.enc -out TexteBasiqueDec3.txt

#openssl enc -d -pbkdf2 -aes-256-ctr -iv 0123456789 -k 0123456789 -in TexteBasique2.enc -out TexteBasiqueDec4.txt

##  Déchiffrer un texte raccourci

#openssl enc -d -pbkdf2 -aes-256-ctr -iv 0123456789 -k 0123456789 -in TexteBasiqueRaccourci.enc -out TexteBasiqueDecRac1.txt

#openssl enc -d -pbkdf2 -aes-256-ctr -iv 0123456789 -k 0123456789 -in TexteBasiqueRaccourci2.enc -out TexteBasiqueDecRac2.txt

#openssl enc -d -pbkdf2 -aes-256-ctr -iv 0123456789 -k 0123456789 -in TexteBasiquePerturbe.enc -out TexteBasiqueDecPert3.txt


###########################################
##
## EXERCICE 5, Arithmétique modulaire, avec le package gmpy2
##      py -m pip install gmpy2
##
###########################################

import gmpy2 as gm

##  On commence par vérifier que vous connaissez l'arithmétique modulaire
##  Notamment la structure de Z/nZ, quand n premier
##  Recherche de grands nombres premiers



p=gm.next_prime(123456)  ## attention au type
##  123457

##  Inversion modulaire
pow(456,-1,p)
a=456*int(pow(456,-1,p))
a/int(p)
a-23*int(p)

#######################################################
## Z/nZ cyclique, un relativement grand nombre premier
######################################################

##  On peut factoriser p-1, ici c'est facile, 
p_1=(2**6)*3*643

## test pour un générateur
e1=(2**5)*3*643   ## vaut (p-1)/2
e2=(2**6)*643     ## vaut (p-1)/3
e3=(2**6)*3       ## vaut (p-1)/643

## On peut vérifier directement que 5 est générateur
g=5
pow(g,e1,p)
pow(g,e2,p)
pow(g,e3,p)

## Une vérification en direct

V=[pow(g,k,p) for k in range(p-1)]   ### On a toutes les puissances de 5
VS=sorted(V)                         ### ... rangées dans l'ordre croissant

## Les 20 premiers
[int(VS[k]) for k in range(20) ]

DIFF=[int(VS[k+1])-int(VS[k]) for k in range(p-2) ]  ### Examinez alors le minimum et le maximum ...


###########################################
##
## EXERCICE 6 : Inversion de l'exponentiation modulaire pour un nombre premier
##  prendre des petits nombres, bien détailler chaque étape
##
###########################################


p=101
e=3
d=pow(e,-1,100)
d

x=5
y=pow(x,e,p)
pow(y,d,p)

###########################################
##
## EXERCICE 7 : Inversion de l'exponentiation modulaire pour n=p*q
##
###########################################


p=103
q=211
n=p*q
phi=(p-1)*(q-1)

e=11      ## par exemple
gm.gcd(e,phi)

d=pow(e,-1,phi)

x=5            ## peut être fait avec d'autres valeurs de x
y=pow(x,e,n)
pow(y,d,n)


###########################################
## EXERCICE 8 
##  Une démo complète du RSA,  
############################################

Message='Bonjour à tous, voici un message signé RSA'     
m_condense=int(hs.sha256(Message.encode('utf-8')).hexdigest(),base=16) % (2**32)   ## On parle aussi d'emprunte

m_condense
#=> 397744965304403079711293369828761321954767970283006466044059397375086812920

p=gm.next_prime(10**18+11**15)

###    mpz(1004177248169415667)

q=gm.next_prime(2*(10**15)+13**11)

###    mpz(2001792160394051)

n=int(p*q)
phi=int((p-1)*(q-1))
### n   2010154143031607682800177132997017
### phi 2010154143031606676621136803187300

v=2**16+1
### v   65537

s=pow(v,-1,phi)  
(s*v) % phi  
#=>  1 

signature=pow(m_condense,s,n)

## On vérifie

verification=pow(signature,v,n)


#########################################
## EXERCICE 9
##  RSA comme mode de chiffrement, en prime, nous n'avons pas eu le temps de le voir  
#########################################

p=gm.next_prime(64513789)  ##  64513817
q=gm.next_prime(1846735)   ##  1846751
n=p*q
M=705462    ### Le message à chiffrer, il est forcément très court, inférieur à n

phi=(p-1)*(q-1)
phi
#=> mpz(119140889698000), 
#=> pour déchiffrer d_publique=mpz(51060381299143)

n=119140956058567
e=7
d=pow(e,-1,phi)

C=pow(M,e,n)   ## on utilise e comme clé publique de chiffrement ici
C
#=> 28984844843297

pow(C,d,n)   ## Vous retrouvez M



######################
##
##   EXO 10 : Echange de clé Diffie Hellman, en groupe
##
######################

## On a pris le nombre premier suivant
p=2470094699
q=1235047349   ## vaut p-1 qui est ici aussi premier, ce ,nombre est "accessoire", il n'est pas fourno 
g=1259         ## on va élevé ce nombre g à des puissances modulo p


## Alice et Bob communiquent à distance, p et g sont connus d'Alice et de Bob, voire sont même publics

## Alice choisi un nombre a aléatoire, inférieur à p, qui reste secret !
a=97684517
## Elle publie A
A=pow(g,a,p)  ## 1544544945

## Bob choisi un nombre aléatoire b, de même
b=97846513
## Il publie ensuite B
B=pow(g,b,p)  ## 1082475948

##  La clé vaut K=pow(A,b,p)=pow(B,a,p)
K1=pow(A,b,p)
K2=pow(B,a,p)

## Vous pouvez vérifier que ces valeurs sont égales à 1900036241


###############################
###
###    EXO 11 . CHIFFREMENT ELGAMAL
### 
###############################

## Alice demande à Bob de lui envoyer un "court message"
## Ce message peut être un mot de passe, ou une autre information confidentielle, ..

## Comme dans le cas de Diffie Hellman, un nombre premier p, et un nombre g qui, à défut d'être un générateur, a un ordre très élevé

p=71398895185373183
g=123457

## Alice choisi un nombre a aléatoire :
a=7894651
## Elle publie A
A=pow(g,a,p)   ## 57037618745651077 

## Bob va envoyer le message suivant :
M=1234560000654987

## Pour cela, il va aussi choisir b aléatoire
b=16544981
## et calculer B
B=pow(g,b,p)   ## 29750039833622143

## Il en déduit une "clé éphémère" qui ne utilisée qu'une seule fois
K1=pow(A,b,p)  ## 39736966296463086

## Il calcule C
C=(K1*M) % p     ## 61392365571063528

## Le message chiffré envoyé à Alice est constitué de B et C, soit : 29750039833622143 et 61392365571063528

## A la réception du message de Bob, Alice calcule K2, et retrouve la valeur de K1 camcumée par Bobo, mais qui est restée secrère
K2=pow(B,a,p)

## Elle inverse K2 modulo p
KI=pow(K2,-1,p)    ## 62265295666632694

## et retrouve le message M
MDecrypt=(KI*C)%p  ##  1234560000654987


###############################
###
###    EXO 12 . SIGNATURE ELGAMAL
### 
###############################

##  Même p, hash simplifié modulo 2**54, même g

import hashlib
import math

Texte="Voici un texte avec une petite signature"

H_Texte=hashlib.sha256("Texte".encode('utf-8'))

N_Texte=int(H_Texte.hexdigest(),base=16) % (2**54)
m=N_Texte

## C'est cela qu'on va signer

x=6498721
y=pow(g,x,p)   ##  55005403469591723

## k premier avec p-1
k=435197813
math.gcd(k,p-1)

r=pow(g,k,p)     ##  28259511640764293
kI=pow(k,-1,p-1) ##  34488422320278865

s=((N_Texte-x*r)*kI) % (p-1) ## 41803248468252703

Verif1=pow(g,N_Texte,p)              ## 24089878976828504
Verif2=(pow(r,s,p)*pow(y,r,p)) % p   ## 24089878976828504
 










