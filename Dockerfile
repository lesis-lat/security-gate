FROM perl:5.42

COPY . /usr/src/security-gate
WORKDIR /usr/src/security-gate

RUN cpanm --installdeps .

ENTRYPOINT [ "perl", "./security-gate.pl" ]