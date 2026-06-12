# syntax=docker/dockerfile:1.7
FROM node:20-alpine AS build

WORKDIR /app

COPY frontend/package*.json ./

RUN npm install

COPY frontend/ .

ARG VITE_API_BASE=/api
ARG VITE_ACCESS_PASS=
ENV VITE_API_BASE=${VITE_API_BASE}
ENV VITE_ACCESS_PASS=${VITE_ACCESS_PASS}

RUN npm run build

FROM nginx:1.27-alpine

COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]

