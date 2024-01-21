# Use an official base image (e.g., Debian)
FROM debian:latest

# Set the working directory
WORKDIR /aphash

# Install dependencies (adjust based on your application)
RUN apt-get update && \
    apt-get install -y libssl-dev gcc make apt-utils fish

# Copy the local code to the container
COPY . .

# sudo docker build -t aphash .
# sudo docker run -it --rm -v /home/xepho/Bureau/aphash:/aphash aphash