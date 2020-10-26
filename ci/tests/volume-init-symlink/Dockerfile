FROM nginx:alpine
RUN mkdir -p /usr/share/nginx/html
RUN mkdir -p /subdir/masked
RUN ln -s /subdir/masked /usr/share/nginx/html
RUN echo "from-dockerfile" > /subdir/masked/masked.html
