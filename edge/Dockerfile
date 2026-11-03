FROM node:22-alpine
ENV NODE_ENV=production PORT=8080
WORKDIR /opt/arixshield
COPY --chown=65532:65532 api ./api
COPY --chown=65532:65532 edge ./edge
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD node edge/healthcheck.mjs
CMD ["node", "edge/gateway.mjs"]
