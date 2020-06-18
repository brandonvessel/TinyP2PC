gcc *.c -pthread -lcrypto -o peer
gcc *.c -pthread -lcrypto -DPRIVATEKEY -o master_peer