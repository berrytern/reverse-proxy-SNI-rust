# Start with a rust alpine image
FROM rust:1-alpine3.20
# This is important, see https://github.com/rust-lang/docker-rust/issues/85
ENV RUSTFLAGS="-C target-feature=-crt-static"
# if needed, add additional dependencies here
RUN apk add --no-cache musl-dev pkgconfig openssl-dev
# set the workdir and copy the source into it
WORKDIR /app

COPY ./Cargo.toml ./Cargo.lock /app

RUN mkdir src/ \
    && echo 'fn main() {println!("Hello, world!");}' >> ./src/main.rs \
    && cargo build --release
RUN rm -f ./src/main.rs && rm -f ./target/release/deps/api_gtw*

COPY ./src/ /app/src
# do a release build
RUN cargo build --release && strip target/release/api-gtw

# use a plain alpine image, the alpine version needs to match the builder
FROM alpine:3.20
# if needed, install additional dependencies here
RUN apk add --no-cache libgcc openssl-dev
# copy the binary into the final image
COPY --from=0 /app/target/release/api-gtw .
EXPOSE 443
EXPOSE 80
# set the binary as entrypoint
ENTRYPOINT ["/api-gtw"]