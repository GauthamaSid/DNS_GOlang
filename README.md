# Redis-backed DNS Server with Go and Miekg

This project is a DNS server implementation in Go that utilizes Redis for caching DNS responses. It leverages the Miekg DNS library for handling DNS protocols.

## Features

- **Redis Caching**: Utilizes Redis as a cache to improve response times for frequently requested DNS records.
- **Miekg DNS Library**: Uses the Miekg DNS library for efficient handling of DNS protocols.

## Requirements

- Go (1.20+)
- Redis Server (2.8+)


## Usage

Once the server is up and running, configure your DNS resolver to use this server's address for DNS queries.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgements

- [Miekg DNS Library](https://github.com/miekg/dns)
- [Redis](https://redis.io/)
