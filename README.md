

## Build
```
mvn clean install
```

## Use
```
java -jar target/trino-jwt-gen-cli-1.0-SNAPSHOT-spring-boot.jar execute_http_request --secret test  --request http://localhost:8080/v1/service
```