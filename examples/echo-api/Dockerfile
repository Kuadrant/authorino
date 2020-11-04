FROM ruby:2.7

RUN bundle config --global frozen 1

WORKDIR /usr/src/app

ENV PORT=8080 \
    ENVIRONMENT=production

COPY Gemfile Gemfile.lock ./
RUN bundle install

COPY . .

ENTRYPOINT [ "sh", "-c" ]
CMD ["exec rackup --port $PORT --env $ENVIRONMENT"]
