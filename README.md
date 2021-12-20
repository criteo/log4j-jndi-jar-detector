# Log4j JNDI Jar Detector

## Purpose

This application is able to detect jars used by running processes and vulnerable
to CVE-2021-44228.

The application lists processes running java, parses the command lines and environment
variables to find the jars from the classpaths and other arguments. Then, for each
detected jar, it analyzes its content to find the version and check if the
JNDILookup class is present in the jar in order to confirm whether the jar is
vulnerable.

Once all jars are analyzed, it reports the results on stdout or in an Elasticsearch
cluster in case the data is collected from a fleet of servers.

## Options

    Detect the running jars vulnerable to log4j JNDI expoits

    Usage:
    log4j-jndi-jar-detector [flags]

    Flags:
    -d, --daemon              enable/disable daemon mode
    -h, --help                help for log4j-jndi-jar-detector
    -i, --interval duration   duration between intervals in daemon mode (default 15m0s)
    -r, --reporters strings   Reporters to use (stdout, elasticsearch) (default [stdout])
        --verbose             enable verbose logs

### Stdout Reporter

This is the most basic reporter displaying the jars found to be vulnerable on the
standard output. It's the simplest way to check if one computer is vulnerable.

### Elasticsearch Reporter

Elasticsearch reporter allows the application running on a fleet of servers to report
in one location in order to take global decisive actions for mitigating the issue.

The configuration is done through environment variables

| Name | Value |
|------|-------|
| ES_URL | The URL to the elasticsearch cluster |
| ES_USERNAME | The username to authenticate with |
| ES_PASSWORD | The password for the username to authenticate with |
| ES_INDEX | The index where to store the events |

This reporter generates 3 kind of events:
- Host assessments, reporting on the number of jars vulnerable on one host.
- Application assessments, reporting details about the application found to be vulnerable.
- Application assessments errors, reporting audit errors for a given application.