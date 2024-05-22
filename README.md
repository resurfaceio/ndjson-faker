# resurfaceio-simulator
Simulate API calls and import into Resurface database

This open source Java utility generates simulated API calls (in [NDJSON format](https://resurface.io/json.html))
and sends these to a remote Resurface database. This command-line utility works with Resurface databases on Kubernetes or Docker.

[![CodeFactor](https://www.codefactor.io/repository/github/resurfaceio/simulator/badge)](https://www.codefactor.io/repository/github/resurfaceio/simulator)
[![License](https://img.shields.io/github/license/resurfaceio/simulator)](https://github.com/resurfaceio/simulator/blob/v3.6.x/LICENSE)
[![Contributing](https://img.shields.io/badge/contributions-welcome-green.svg)](https://github.com/resurfaceio/simulator/blob/v3.6.x/CONTRIBUTING.md)

## Usage

Download executable jar:
```
wget https://dl.cloudsmith.io/public/resurfaceio/public/maven/io/resurface/resurfaceio-simulator/3.6.5/resurfaceio-simulator-3.6.5.jar
```

Run with default dialect:
```
java -DWORKLOAD=Coinbroker -DHOST=localhost -DPORT=443 -DBATCH_SIZE=128 -DCLOCK_SKEW_DAYS=0 -DLIMIT_MESSAGES=0 -DLIMIT_MILLIS=0 -DSLEEP_PER_BATCH=0 -Xmx512M -jar resurfaceio-simulator-3.6.5.jar
```

Run with API Connect dialect:
```
java -DDIALECT=ibm -DWORKLOAD=RestSmall2 -DHOST=localhost -DPORT=443 -DBATCH_SIZE=128 -DCLOCK_SKEW_DAYS=0 -DLIMIT_MESSAGES=0 -DLIMIT_MILLIS=0 -DSLEEP_PER_BATCH=0 -Xmx512M -jar resurfaceio-simulator-3.6.5.jar
```

## Parameters

```
WORKLOAD: workload implementation class
HOST: machine name for remote database
PORT: network port for remote database (80 or 443 for Kubernetes, 7701 for Docker)

BATCH_SIZE: default is '128', messages sent in a single POST
CLOCK_SKEW_DAYS: default is '0' (none), rewind virtual clock & advance faster
DIALECT: default is 'default' (Resurface format), set to 'ibm' for API Connect
LIMIT_MESSAGES: default is '0' (unlimited), quit after this many messages
LIMIT_MILLIS: default is '0' (unlimited), quit after this many milliseconds
SLEEP_PER_BATCH: default is '0' (none), pause in millis between batches
URL: override HOST and PORT with custom URL for remote database
```

## Available Workloads

* **Minimum** - empty calls with method, url and response code only (12 byte/call)
* **Coinbroker** (default) - REST and GraphQL calls with injected failures and attacks (500 byte/call average)
* **RestSmall3** - REST calls with randomized url path, headers, and JSON bodies (2 KB/call average)
* **RestLarge3** - REST calls with randomized url path, headers, and JSON bodies (8 KB/call average)
* **ScrapingStuffing** - REST calls including scraping and stuffing attacks (X KB/call average)

## Dependencies

* Java 17
* [datafaker-net/datafaker](https://github.com/datafaker-net/datafaker)
* [DiUS/java-faker](https://github.com/DiUS/java-faker)
* [resurfaceio/ndjson](https://github.com/resurfaceio/ndjson)

## Installing with Maven

⚠️ We publish our official binaries on [CloudSmith](https://cloudsmith.com) rather than Maven Central, because CloudSmith
is awesome.

If you want to call this utility from your own Java application, add these sections to `pom.xml` to install:

```xml
<dependency>
    <groupId>io.resurface</groupId>
    <artifactId>resurfaceio-simulator</artifactId>
    <version>3.6.5</version>
</dependency>
```

```xml
<repositories>
    <repository>
        <id>resurfaceio-public</id>
        <url>https://dl.cloudsmith.io/public/resurfaceio/public/maven/</url>
        <releases>
            <enabled>true</enabled>
            <updatePolicy>always</updatePolicy>
        </releases>
    </repository>
</repositories>
```

---
<small>&copy; 2016-2024 <a href="https://resurface.io">Graylog, Inc.</a></small>
