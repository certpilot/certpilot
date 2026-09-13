# syntax=docker/dockerfile:1

# The console, served by nginx.
#
# The build context is the repository root, not frontend/. The previous version
# of this file used `COPY ../deploy/docker/nginx.conf`, which cannot work: COPY
# resolves inside the build context and refuses to climb out of it. That one
# line is why this image had never been built.
FROM --platform=$BUILDPLATFORM node:22-alpine AS builder

WORKDIR /app

# Manifests first so a source edit does not invalidate the install layer.
COPY frontend/package.json frontend/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci

COPY frontend/ ./

# `npm run build` is `vue-tsc && vite build`, so a type error fails the image
# rather than shipping a console that compiles to nothing.
RUN npm run build

FROM nginx:1.27-alpine

# Reachable now that the context starts at the repository root.
COPY deploy/docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
