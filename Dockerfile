# 1. This tells docker to use the Rust official image
FROM rust:latest AS builder
RUN apt-get update && apt-get install -y git && apt-get install -y cmake python3-pip
# Build your program for release
RUN pip3 install ziglang
RUN cargo install cargo-lambda

WORKDIR /code
# 2. Copy the files in your machine to the Docker image
COPY ./ .

RUN  cargo lambda build --release --arm64
RUN ls -all

FROM public.ecr.aws/lambda/provided:al2.2022.06.14.15-arm64 AS run
ARG AUTHORIZER_VERSION="v1"
COPY --from=builder /code/target/lambda/${AUTHORIZER_VERSION}-authorizer/bootstrap  ${LAMBDA_RUNTIME_DIR}
CMD ["rust-lambda-authorizer"]