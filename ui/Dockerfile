FROM nginx:alpine

COPY index.html /usr/share/nginx/html/index.html

# Proxy /api/* and /health to the backend container
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
