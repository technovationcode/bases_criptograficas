# bases_criptograficas

Basado en el libro "Cryptography and Cryptoanalysis in Java" de Stefania Loredana Nita y Marius Lulian Mihalescu.

Implementación de algoritmos criptográficos.

En el paquete base. 
Encontrarás ejemplos de:<br>
-Hashing 
<br>
-Encriptación RSA<br>
<br>
La encriptación se divide en encriptación simétrica y asimétrica.

<b>ENCRIPTACIÓN SIMÉTRICA</b><br>

Algunos ejemplos de encriptación simétrica más antiguo son el cifrado de Cesar o el cifrado Vigenere.<br>

En encryption.symmetric.primitives<br>
Encontrarás los algoritmos implementados de Cesar y Vigenere.

Además del más utilizado actualmente que es el AES-256

<b>ENCRIPTACIÓN ASIMÉTRICA</b>

También conocido como de llave pública.

En encryption.asymetric
Encontrarás 2 algoritmos ampliamente utilizados. RSA y ElGamal. 

la encriptación asimétrica es la base de las firmas digitales.

En encryption.asymetric.signatures encontrarás 3 algoritmos para la generación y verificación de firmas digitales.

-RSA

-ElGamal

-DSA

También se han agregado 2 esquemas de identificación, en el paquete schemes.

-FFSScheme es un ejemplo basado en el esquema zero-knoledge proof

-AesNtru, es un ejemplo de algoritmo basado en retículos, el cual pone a prueba a los ataques de computación cuántica.





