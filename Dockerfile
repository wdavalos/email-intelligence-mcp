FROM apify/actor-python:3.14

COPY --chown=myuser:myuser requirements.txt ./

RUN echo "Python version:" && python --version \
    && pip --version \
    && pip install -r requirements.txt \
    && echo "All installed Python packages:" && pip freeze

COPY --chown=myuser:myuser . ./

RUN python -m compileall -q .

CMD ["python", "-m", "email_intelligence_mcp"]