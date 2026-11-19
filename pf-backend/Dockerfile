FROM node:22-slim
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --chown=node:node . .
RUN mkdir -p /data && chown node:node /data
ENV NODE_ENV=production PORT=5000 DB_PATH=/data/pratishtha.db
VOLUME ["/data"]
EXPOSE 5000
USER node
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||5000)+'/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node","--disable-warning=ExperimentalWarning","server.js"]
