# HTTPS-OpenSSL
Example of HTTPS communication with OpenSSL in C++  
https_server.c contains code for the server responds to the client's request through https. //141  
https is the process of adding an encryption between http and tcp, and the code implementation differs from the 
general TCP Server in two ways: //164  
After accpet(), the ssl takes over the socket, completing operations such as negotiating the encryption 
algorithm and exchanging keys. //34  
Then we replace send() and recv() with SSL's SSL_write() and SSL_read() functions. //168  
The OpenSSL Project develops and maintains the OpenSSL software - a robust, commercial-grade, full-featured 
toolkit for general-purpose cryptography and secure communication.  
https_client.c contains code for the client to request a page from the server through https which is implemented via openssl.
