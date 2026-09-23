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
# ffmpeg provides the ffprobe binary used to measure real stream
# resolution/fps for quality-tier probing (see probe.js) - shelled out to
# directly rather than pulled in as an npm package, since ffprobe is a
# standalone binary, not a Node library.
RUN apk add --no-cache fontconfig ttf-dejavu ffmpeg

COPY package*.json ./

RUN npm ci --omit=dev

COPY . .

EXPOSE 2323

ENV PORT=2323
ENV HOST=0.0.0.0

CMD ["npm", "start"]
