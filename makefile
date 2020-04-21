all: ClientWithoutSecurity.java ServerWithoutSecurity.java PrivateKeyReader.java PublicKeyReader.java
	javac ClientWithoutSecurity.java ServerWithoutSecurity.java PrivateKeyReader.java PublicKeyReader.java

test: ClientWithoutSecurity.class ServerWithoutSecurity.class PrivateKeyReader.class PublicKeyReader.class


clean:
	rm ClientWithoutSecurity.class
	rm ServerWithoutSecurity.class
	rm PrivateKeyReader.class
	rm PublicKeyReader.class