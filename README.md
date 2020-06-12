# Blimp CLI

[![Build Status](https://circleci.com/gh/kelda/blimp.svg?style=svg)](https://circleci.com/gh/kelda/blimp)
[![Go Report Card](https://goreportcard.com/badge/github.com/kelda/blimp?)](https://goreportcard.com/report/github.com/kelda/blimp)
[![Slack](https://kelda.io/img/slack-badge.svg)](http://slack.kelda.io)

This repository contains the CLI for [Blimp](https://kelda.io/blimp).
Blimp lets you develop in the cloud, reducing CPU and RAM usage on your laptop.
It supports the same
[configuration](https://docs.docker.com/compose/compose-file) and
[workflows](https://devcenter.heroku.com/articles/local-development-with-docker-compose)
as [Docker Compose](https://docs.docker.com/compose/).

This repository is also used for issue tracking and feature requests.

## How it Works

* The containers run in a remote Kubernetes cluster. [compose-go](https://github.com/compose-spec/compose-go) parses
  compose files into a standard format, which is then deployed by the Blimp
  Cloud.
* [Localhost network tunnels](https://docs.docker.com/compose/compose-file/#ports) are implemented over [gRPC streams](https://github.com/kelda/blimp/blob/master/_proto/blimp/node/v0/controller.proto#L10).
* [Bind volumes](https://docs.docker.com/compose/compose-file/#volumes) are
  implemented with [Syncthing](https://syncthing.net/). The Syncthing
  connection is also tunnelled over the gRPC stream.

## Installation

`blimp` has been tested on Mac, Linux, and Windows WSL.

```shell
curl -fsSL 'https://kelda.io/get-blimp.sh' | sh
```

Or, on Homebrew:

```shell
brew install kelda/tools/blimp
```

## Example

```
# Download the example.
git clone https://github.com/kelda/node-todo
cd node-todo

# Create a Blimp sandbox.
blimp login

# Boot the docker-compose.yml.
blimp up

# You can now interact with your containers as if they were running locally.
# Edit files.
vim app/routes.js

# Access the app.
curl localhost:8080
```

## Documentation

* [Other examples](https://kelda.io/blimp/docs/examples) of developing
  with Blimp.
* [Design principles](https://kelda.io/blimp/docs/#design-principles) (be
  light, require zero setup, and require zero workflow changes)
* [Basic usage analytics](https://kelda.io/blimp/docs/security/#services-used-and-data-stored-in-them)
  are collected by default (you can opt out).
* [The Kelda Slack](https://slack.kelda.io) is the best way to reach the maintainers.

## Contributing

Contributions are very much welcome!  Check out the [contribution
guide](CONTRIBUTING.md) to get started.
