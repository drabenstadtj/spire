FROM almalinux:latest

# Install basic packages
RUN dnf install -y vim make gcc iproute-tc

# Install Spire dependencies
RUN dnf install -y dnf-plugins-core
RUN dnf config-manager --set-enabled crb
RUN dnf install -y openssl-devel flex byacc qt5-devel cmake python

# Install debugging tools
RUN dnf install -y gdb valgrind

# Copy Spire source code
COPY . /app/spire
WORKDIR /app/spire

# Set up config files
RUN cd example_conf; ./install_conf.sh conf_4 

# Build Spire core (Spines, Prime, SCADA Master, benchmark)
RUN make core

# Run the Python script to generate missing keys
RUN python /app/spire/check_and_generate_keys.py

#ENTRYPOINT /bin/bash
