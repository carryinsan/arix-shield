FROM node:22-alpine
ENV NODE_ENV=production PORT=8080
WORKDIR /opt/arixshield
COPY --chown=node:node api ./api
COPY --chown=node:node edge ./edge
USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD node edge/healthcheck.mjs
CMD ["node", "edge/gateway.mjs"]
