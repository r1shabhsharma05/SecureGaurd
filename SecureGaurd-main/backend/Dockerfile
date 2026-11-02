# Backend image (Node 22 LTS). Prisma client is generated at build time from
# prisma/schema.prisma; migrations run at container start (see
# docker-compose.yml), never at image build, so the image stays
# database-agnostic.
FROM node:22-alpine

WORKDIR /app

COPY package.json package-lock.json ./
# Full install (dev included): `npm run build` runs `prisma generate` and
# prisma is a devDependency. Mirrors the hosted Render build command.
RUN npm ci

COPY prisma ./prisma
COPY config ./config
COPY middleware ./middleware
COPY routes ./routes
COPY services ./services
COPY utils ./utils
COPY prismaClient.js server.js ./

RUN npm run build

EXPOSE 5000
CMD ["node", "server.js"]
