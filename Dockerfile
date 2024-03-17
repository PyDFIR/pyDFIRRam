FROM ubuntu:latest

ADD ./ /app

WORKDIR /app
RUN mkdir /work
RUN mkdir /dump


COPY ./docker/entrypoint.sh /work/entrypoint.sh
RUN apt update && apt install  openssh-server sudo python3 curl -y
RUN curl -sSL https://install.python-poetry.org | python3 -

RUN /root/.local/bin/poetry install

RUN useradd -rm -d /home/ubuntu -s /bin/bash -g root -G sudo -u 1000 test 

RUN  echo 'test:test' | chpasswd

RUN service ssh start

EXPOSE 22
EXPOSE 8081

CMD ["/usr/sbin/sshd","-D"]
RUN chmod -R 765 /work/*.sh
ENTRYPOINT ["/work/entrypoint.sh"]
CMD ["server"]
