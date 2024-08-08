# Use an official Python runtime as a parent image
FROM python:3.9-slim-buster

# Set the working directory in the container to /app
WORKDIR /app

# Add the current directory contents into the container at /app
ADD . /app

# Install ping, curl, and wget
RUN apt-get update && \
    apt-get install -y iputils-ping curl wget && \
    rm -rf /var/lib/apt/lists/*

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir Werkzeug==3.0.3
RUN pip install --no-cache-dir Flask==3.0.3
RUN pip install --no-cache-dir requests==2.31.0
RUN pip install --no-cache-dir jwt==1.3.1
RUN pip install --no-cache-dir jwcrypto==1.5.6
RUN pip install --no-cache-dir PyJWT==2.8.0
RUN pip install --no-cache-dir python-keycloak==3.12.0
RUN pip install --no-cache-dir Authlib==1.3.0
RUN pip install --no-cache-dir Flask-HTTPAuth==4.8.0
RUN pip install --no-cache-dir Flask-Login==0.6.3
RUN pip install --no-cache-dir cryptography==42.0.5
RUN pip install --no-cache-dir python-dotenv==1.0.1

# Set environment variables

# Make port 8888 available to the world outside this container
EXPOSE 8000/tcp

# Run app.py when the container launches
CMD ["python", "main.py"]
