# Dockerfile

# Use Python 3.9 as the base image
FROM python:3.9

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install the dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the current directory contents into the container at /app
COPY . .

# Expose port 5000
EXPOSE 5000

# Run the Flask app
CMD ["python", "-m", "flask", "run", "--host=0.0.0.0", "--port=5000"]