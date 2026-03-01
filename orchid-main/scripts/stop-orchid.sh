#!/bin/bash

echo "Stopping Orchid System..."
docker-compose down

echo "Cleaning up..."
docker system prune -f

echo "Orchid System stopped."
