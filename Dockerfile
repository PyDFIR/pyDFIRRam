FROM ubuntu:latest

ADD ./ /app

WORKDIR /app

RUN apt update && apt install  openssh-server sudo python3 curl -y
RUN curl -sSL https://install.python-poetry.org | python3 -

RUN /root/.local/bin/poetry install

RUN useradd -rm -d /home/ubuntu -s /bin/bash -g root -G sudo -u 1000 test 

RUN  echo 'test:test' | chpasswd

RUN service ssh start

EXPOSE 22

CMD ["/usr/sbin/sshd","-D"]