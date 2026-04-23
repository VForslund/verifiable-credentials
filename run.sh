#!/bin/bash

echo "Building the frontend..."
cd front
npm install
npx ng build
cd ..

echo "Starting the backend..."
cd backend
./mvnw spring-boot:run

