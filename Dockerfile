FROM almalinux:latest

# Install basic packages
RUN dnf install -y vim make gcc 

# Install Spire dependencies
RUN dnf install -y dnf-plugins-core
RUN dnf config-manager --set-enabled crb
RUN dnf install -y openssl-devel flex byacc qt5-devel cmake python

# Install debugging tools
RUN dnf install -y gdb valgrind

# Copy Spire source code
COPY . /app/spire
WORKDIR /app/spire

# Copy pre-generated keys
COPY prebuilt_keys/spines /app/spire/spines/daemon/keys
COPY prebuilt_keys/prime /app/spire/prime/bin/keys
COPY prebuilt_keys/scada /app/spire/scada_master/sm_keys  

# Set up config files
RUN cd example_conf; ./install_conf.sh conf_4 

# Build Spire core (Spines, Prime, SCADA Master, benchmark)
RUN make core

#ENTRYPOINT /bin/bash
