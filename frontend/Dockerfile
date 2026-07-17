# --- Build stage: compile the React app to static assets ---
FROM node:20-slim AS build

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install

COPY . .
RUN npm run build

# --- Serve stage: static files behind nginx, which also proxies /api ---
FROM nginx:1.27-alpine

# SPA + /api proxy config (replaces the default server block).
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
