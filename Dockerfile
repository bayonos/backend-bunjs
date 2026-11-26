FROM oven/bun:1-alpine

WORKDIR /app

COPY package.json tsconfig.json ./
COPY src ./src

ENV HOST=0.0.0.0
ENV PORT=8080
EXPOSE 8080

CMD ["bun", "run", "src/main.ts"]
