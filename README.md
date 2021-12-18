# Log4j JNDI Jar Detector

This application is able to detect jars used by running processes and vulnerable
to CVE-2021-44228.

The application lists processes running java, parses the command lines and environment
variables to find the jars from the classpaths and other arguments. Then, for each
detected jar, it analyzes its content to find the version and check if the
JNDILookup class is present in the jar in order to confirm whether the jar is
vulnerable.

Once all jars are analyzed, it reports the results on stdout or in an Elasticsearch
cluster for those who need to collect the data from a fleet of servers.
