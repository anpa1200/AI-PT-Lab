FROM nginx:alpine

COPY index.html /usr/share/nginx/html/index.html

# Proxy /api/* and /health to the backend container
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Suppress notice-level startup logs (worker process announcements etc.)
COPY nginx-main.conf /etc/nginx/nginx.conf

EXPOSE 80
