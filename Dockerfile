FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install all dependencies (including dev for TypeScript)
RUN npm install

# Copy source code
COPY src/ ./src/

# Build the application
RUN npm run build

# Remove dev dependencies for production
RUN npm prune --omit=dev

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S mesh-scanner -u 1001

# Change ownership of the app directory
RUN chown -R mesh-scanner:nodejs /app

# Switch to non-root user
USER mesh-scanner

# Start the application
CMD ["node", "build/index.js"]
