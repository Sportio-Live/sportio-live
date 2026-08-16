FROM node:24-alpine

WORKDIR /usr/src/app

COPY package*.json ./

RUN npm ci --omit=dev

COPY . .

EXPOSE 2323

ENV PORT=2323
ENV HOST=0.0.0.0

CMD ["npm", "start"]
