# docker build --tag=trust-agent-container --build-arg http_proxy=<proxy> --build-arg https_proxy=<proxy> .
# export BEARER_TOKEN=`curl --request POST https://10.80.245.183:8444/aas/token  --noproxy "*" -k -d '{"username" : "superadmin", "password" : "superAdminPass"}'`
# docker run -it --rm --privileged -v /dev/tpm0:/dev/tpm0 -p 1443:1443 --env BEARER_TOKEN=$BEARER_TOKEN --env-file ./answer.txt trust-agent-container /bin/bash
FROM fedora:29

RUN yum install -y tpm2-tools tpm2-tss tpm2-abrmd dmidecode redhat-lsb-core

RUN mkdir -p /opt/trustagent/bin \
             /opt/trustagent/configuration/cacerts \
             /opt/trustagent/configuration/jwt \
             /opt/trustagent/var/system-info \
             /opt/trustagent/var/ramfs \
             /var/log/trustagent

COPY tagent /opt/trustagent/bin/tagent

RUN ln -s /opt/trustagent/bin/tagent /usr/bin/tagent

RUN useradd --comment "Trust Agent User" --home /opt/trustagent --system --shell /bin/false tagent && usermod --lock tagent
