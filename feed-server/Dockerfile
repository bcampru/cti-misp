FROM node:16

# Create app directory
WORKDIR /opt/feed-server
COPY . .

# Install app dependencies
# A wildcard is used to ensure both package.json AND package-lock.json are copied
# where available (npm@5+)

# If you are building your code for production
RUN npm ci --omit=dev

# Bundle app source

EXPOSE 8080
CMD [ "node", "src/index.js" ]