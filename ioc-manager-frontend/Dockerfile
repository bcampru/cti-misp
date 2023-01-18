# pull official base image
FROM node:slim

# set working directory
WORKDIR /app

EXPOSE 3000

# add `/app/node_modules/.bin` to $PATH
ENV PATH /app/node_modules/.bin:$PATH

# install app dependencies
COPY package.json ./
COPY package-lock.json ./
RUN npm install
RUN npm install -g serve

# add app
COPY . ./
RUN npm run build

# start app
CMD ["serve", "-s", "build"]