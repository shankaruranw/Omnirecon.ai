#!/usr/bin/env bash
# Exit on error
set -o errexit

echo "📦 1. Installing Node dependencies..."
npm install

echo "🏗️ 2. Building React frontend..."
npm run build

echo "🐍 3. Installing Python dependencies..."
pip install -r backend/requirements.txt

echo "✅ Build complete!"
