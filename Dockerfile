FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install dependencies
RUN npm ci --only=production

# Copy source code
COPY src/ ./src/

# Build the application
RUN npm run build

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S mesh-scanner -u 1001

# Change ownership of the app directory
RUN chown -R mesh-scanner:nodejs /app

# Switch to non-root user
USER mesh-scanner

# Expose port (if needed)
EXPOSE 3000

# Start the application
CMD ["node", "build/index.js"]
