FROM alpine:3.20
RUN apk add --no-cache socat
CMD ["sh", "-c", "socat -T2 -v UDP-LISTEN:9000,reuseaddr,fork EXEC:'/bin/cat'"]
