all: 
	javac DNSlookup.java
	jar cvfe DNSlookup.jar DNSlookup *.class

run: DNSlookup.jar
	java -jar DNSlookup.jar   199.7.83.42 www.cs.ubc.ca   -t
clean:
	rm -f *.class
	rm -f DNSlookup.jar

verify: DNSlookup.jar
	java -jar DNSlookup.jar   142.103.6.6 cs.ubc.ca
