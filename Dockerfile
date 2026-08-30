FROM node:24-slim

WORKDIR /usr/src/app

# Needed for server-side text rendering (sharp/librsvg, used to turn this
# app's SVG art into real JPEG/PNG files - see server.js's renderSvgToImage).
# Debian's slim image ships with no fonts installed by default, same as
# Alpine did, so without this, librsvg has nothing to draw any <text>
# element with and silently falls back to empty/placeholder glyph boxes
# instead - confirmed as the cause of reports of game times (and other
# rendered text) showing up as garbled boxes rather than the actual text.
# fonts-dejavu-core's sans-serif face is what fontconfig resolves every
# font-family stack in this app's art to, since every one of them ends in
# a generic 'sans-serif' fallback.
#
# Switched from node:24-alpine to this Debian-based image specifically for
# its glibc allocator - Alpine's musl libc was confirmed (via
# /api/admin/diagnostics) to hold onto native memory (sharp/libvips
# renders, EPG gunzip/parse buffers) as "external" process memory that
# never got returned to the OS, keeping RSS pinned near its peak long
# after the actual work was done. glibc's allocator returns freed memory
# to the OS far more readily.
RUN apt-get update && apt-get install -y --no-install-recommends fontconfig fonts-dejavu-core && rm -rf /var/lib/apt/lists/*

COPY package*.json ./

RUN npm ci --omit=dev

COPY . .

EXPOSE 2323

ENV PORT=2323
ENV HOST=0.0.0.0

CMD ["npm", "start"]
