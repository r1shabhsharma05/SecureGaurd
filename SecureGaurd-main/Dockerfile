# Frontend image: Vite build, served by Nginx. In production the app calls
# the API same-origin (/api/*), so Nginx proxies /api/* to the backend
# service — the browser never talks to the backend directly and the
# session cookie stays first-party. See nginx.conf.
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY index.html vite.config.js eslint.config.js ./
COPY public ./public
COPY src ./src
RUN npm run build

FROM nginx:alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
