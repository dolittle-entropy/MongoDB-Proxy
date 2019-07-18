FROM golang:1.12 as build

RUN go get go.mongodb.org/mongo-driver/bson
COPY main.go main.go
RUN CGO_ENABLED=0 go build -a main.go

FROM scratch
COPY --from=build /go/main /bin/proxy
ENTRYPOINT [ "/bin/proxy" ]
