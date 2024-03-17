FROM python:3.11-buster

RUN pip install poetry
ADD ./ /app

WORKDIR /app
RUN mkdir /work
RUN mkdir /dump

COPY ./entrypoint.sh /work/entrypoint.sh

RUN /root/.local/bin/poetry install

EXPOSE 8081

RUN chmod -R 765 /work/*.sh
ENTRYPOINT ["/work/entrypoint.sh"]
CMD ["server"]
