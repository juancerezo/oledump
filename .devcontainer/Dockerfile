FROM mcr.microsoft.com/devcontainers/python:1-3.12-bullseye
SHELL ["/bin/bash", "-c"]

# Node.js & NPM Installation
RUN curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
RUN sudo apt install nodejs

# Upgrade NPM
RUN npm install -g npm@latest

# Install NPM depencencies
RUN npm install -g cloc

# Upgrade PIP
RUN pip install --upgrade pip

USER vscode
ENV PATH="$PATH:/home/vscode/.local/bin"