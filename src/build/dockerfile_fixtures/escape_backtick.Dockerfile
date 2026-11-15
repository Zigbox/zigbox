# escape=`
# Escape with a backtick, and continuations inside exec form.
FROM mcr.microsoft.com/powershell:lts-alpine-3.20
WORKDIR /app
RUN ["pwsh", `
     "-Command", `
     "Write-Output hello"]
COPY a.txt `
     b.txt ./
