FROM node:24-alpine

WORKDIR /usr/src/app

# Needed for server-side text rendering (sharp/librsvg, used to turn this
# app's SVG art into real JPEG/PNG files - see server.js's renderSvgToImage).
# Alpine ships with no fonts installed at all by default, so without this,
# librsvg has nothing to draw any <text> element with and silently falls
# back to empty/placeholder glyph boxes instead - confirmed as the cause of
# reports of game times (and other rendered text) showing up as garbled
# boxes rather than the actual text. ttf-dejavu's sans-serif face is what
# fontconfig resolves every font-family stack in this app's art to, since
# every one of them ends in a generic 'sans-serif' fallback.
RUN apk add --no-cache fontconfig ttf-dejavu

COPY package*.json ./

RUN npm ci --omit=dev

COPY . .

EXPOSE 2323

ENV PORT=2323
ENV HOST=0.0.0.0

CMD ["npm", "start"]
