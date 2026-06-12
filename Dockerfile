# ─────────────────────────────────────────────────────────────
# STAGE 1: Build the React Frontend
# ─────────────────────────────────────────────────────────────
FROM node:18-alpine AS frontend-builder

WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install

# Copy the rest of the frontend code
COPY . .

# Build the React app (creates the 'dist' folder)
RUN npm run build


# ─────────────────────────────────────────────────────────────
# STAGE 2: Setup the Python Backend
# ─────────────────────────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

# Install Python dependencies
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the Python backend code
COPY backend/ ./backend/

# Copy the built frontend from Stage 1
COPY --from=frontend-builder /app/dist/ ./dist/

# Expose the port
EXPOSE 5000

# Set environment variables
ENV FLASK_APP=backend.server
ENV HOST=0.0.0.0
ENV PORT=5000

# Run the application using Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "backend.server:app"]
