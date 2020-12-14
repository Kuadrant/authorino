FROM ruby:2.6

RUN gem update bundler \
 && bundle config --global frozen 1

WORKDIR /usr/src/app

COPY Gemfile Gemfile.lock ./
RUN bundle install

COPY . .

ENTRYPOINT [ "sh", "-c" ]
CMD ["exec rake start"]
