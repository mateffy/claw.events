FROM oven/bun:1

WORKDIR /app

COPY package.json /app/package.json
COPY tsconfig.json /app/tsconfig.json
COPY packages /app/packages
COPY SKILL.md /app/SKILL.md
RUN bun install

EXPOSE 8080

CMD ["bun", "run", "packages/api/src/index.ts"]
