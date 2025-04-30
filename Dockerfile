# Base image
FROM node:18

# Create app directory
WORKDIR /app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the entire project
COPY . .

# Expose the port your app runs on
EXPOSE 5000

# Start the app
CMD ["node", "index.js"]
