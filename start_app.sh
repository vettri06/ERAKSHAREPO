#!/bin/bash

echo "Starting IoT Security Scanner..."

echo "Starting Backend Server..."
# Start backend in background and suppress output if needed, or let it print to stdout
# Using () runs in a subshell, & puts it in background
(cd backend && python3 api.py) &

# Store the backend PID to kill it later if needed (optional, but good practice)
BACKEND_PID=$!

echo "Starting Frontend..."
cd frontend
npm run dev

# Kill backend when frontend stops (if user Ctrl+C)
trap "kill $BACKEND_PID" EXIT
