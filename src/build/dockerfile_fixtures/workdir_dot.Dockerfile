# COPY to `.` and `..` under WORKDIR names a directory, as a trailing slash does.
FROM golang:1.22
WORKDIR /app
COPY main.go .
COPY go.mod ..
COPY go.sum ./
COPY README.md docs
