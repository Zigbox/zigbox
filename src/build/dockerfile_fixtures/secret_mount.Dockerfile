# A secret mount (survey: vllm): refused.
FROM python:3.12
RUN --mount=type=secret,id=hf_token pip install -r requirements.txt
