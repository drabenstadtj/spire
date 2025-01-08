FROM almalinux:latest

# Install basic packages
RUN dnf install -y vim make gcc iproute-tc

# Install Spire dependencies
RUN dnf install -y dnf-plugins-core
RUN dnf config-manager --set-enabled crb
RUN dnf install -y openssl-devel flex byacc qt5-devel cmake python

# Copy files
COPY . /app/spire
WORKDIR /app/spire

# Set up config files
RUN cd example_conf; ./install_conf.sh conf_4 

# Build Spire core (Spines, Prime, SCADA Master, benchmark)
RUN make core

# Build full Spire system
#RUN printf 'Y\n1\n' | make libs
#RUN make

# Generate Keys
RUN cd spines/daemon; bash gen_keys.sh
RUN cd prime/bin; ./gen_keys; ./gen_tpm_keys.sh
RUN cd scada_master; ./gen_keys

#ENTRYPOINT /bin/bash
