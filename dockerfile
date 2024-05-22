# Stage 1: Build the application
FROM node:20.13.1-alpine AS build-stage
WORKDIR /client
COPY ./client/package.json ./
RUN npm install
COPY ./client .
RUN npx nuxi cleanup
RUN npx nuxi generate

# Stage 2: Serve the application with Nginx using PM2
FROM python:3.12.3-alpine AS production-stage
RUN apk add nginx
RUN apk add --update npm
RUN pip install fastapi "uvicorn[standard]" gunicorn
RUN npm install -g pm2
RUN npm install -g npx serve
COPY ./server/requirements.txt ./
RUN pip install -r requirements.txt

WORKDIR /server
COPY ./server .
WORKDIR /client
COPY --from=build-stage /client/.output/public ./.output/public
WORKDIR /
COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 80
COPY ./ecosystem.config.js ./
CMD ["pm2-runtime", "ecosystem.config.js"]
