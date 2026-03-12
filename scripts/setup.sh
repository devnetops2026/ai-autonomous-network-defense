#!/bin/bash

echo "Installing dependencies..."
pip install -r requirements.txt

echo "Installing Mininet..."
sudo apt install -y mininet

echo "Setup complete"