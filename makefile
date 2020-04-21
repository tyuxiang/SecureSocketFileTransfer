all: ClientWithoutSecurity.java ServerWithoutSecurity.java PrivateKeyReader.java PublicKeyReader.java ClientCP1.java ServerCP1.java
	javac ClientWithoutSecurity.java ServerWithoutSecurity.java PrivateKeyReader.java PublicKeyReader.java ClientCP1.java ServerCP1.java

test: ClientWithoutSecurity.class ServerWithoutSecurity.class PrivateKeyReader.class PublicKeyReader.class ClientCP1.class ServerCP1.class


clean:
	rm ClientWithoutSecurity.class
	rm ServerWithoutSecurity.class
	rm PrivateKeyReader.class
	rm PublicKeyReader.class
	rm ClientCP1.class
	rm ServerCP1.class