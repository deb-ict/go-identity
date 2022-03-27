# go-identity
Multi tenant identity server (OIDC/OAuth2.0)

## Work in progress
This repository is work in progress.

## Getting started

#### Running on [Go environment]
```
mkdir -p $GOPATH/src/deb-ict
cd $GOPATH/src/deb-ict
git clone https://github.com/deb-ict/go-identity
cd go-identity
go run ./cmd/server
```

#### Running on [Docker environment]
##### Running docker
```
docker build -f build/container/Dockerfile -t go-identity/server:dev .
docker run -d -p 5000:80 -e MONGO_URI='mongodb://{mongo_uri}:27017' go-identity/server:dev 
```

##### Running docker-compose
```
docker-compose up
```

#### Running on [Kubernetes environment]

*comming soon*


[DEB-ICT]: https://www.deb-ict.com
[Go environment]: https://golang.org/doc/install
[Docker environment]: https://docs.docker.com/engine
[Kubernetes environment]: https://kubernetes.io