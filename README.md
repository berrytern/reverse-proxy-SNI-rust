# API Gateway with SNI Support

## Overview
This project, **api-gtw**, is an API gateway designed to provide support for multiple domains using the same IP and port. It uses Server Name Indication (SNI) to dynamically load SSL certificates and routes requests based on the `Host` header. The gateway forwards incoming requests to target services defined in a configuration file.

## Features
- **SNI Support**: Dynamically loads SSL certificates for different domains.
- **Dynamic Routing**: Routes requests based on the `Host` header to the appropriate target service.
- **Custom Configuration**: Uses a `config.yaml` file to define SSL credentials and target services.
- **Error Handling**: Provides structured JSON responses for errors.

## Requirements
- Rust (Edition 2021)
- A valid SSL certificate for each domain.
- `config.yaml` file to define domain configurations.

## Installation
1. Install Rust by following the instructions at [rust-lang.org](https://www.rust-lang.org/tools/install).
2. Clone this repository:
   ```bash
   git clone git@github.com:berrytern/reverse-proxy-SNI-rust.git
   cd reverse-proxy-SNI-rust
   ```
3. Build the project:
   ```bash
   cargo build --release
   ```

## Usage
1. Create a `config.yaml` file in the root directory with your domain configurations.
    ```bash
    cp config.yaml.example config.yaml
    ```
2. Run the application:
   ```bash
   cargo run --release
   ```
3. The gateway will listen on `0.0.0.0:443` and handle incoming HTTPS requests.

## Key Functionality
### Forwarding Requests
Incoming requests are forwarded to the target service defined for the domain in `config.yaml`. The gateway:
- Preserves the HTTP method and headers.
- Adds an `X-Forwarded-For` header with the client IP.

### Error Responses
Errors are returned as JSON objects with the following structure:
```json
{
    "error": "Description of the error",
    "details": "Optional details",
    "code": "Optional error code"
}
```

### Dynamic SSL Configuration
SSL certificates are loaded dynamically based on the domain using the SNI callback. Ensure that the certificates and private keys are correctly specified in `config.yaml`.

## Logging
The application uses `env_logger` for logging. You can control the logging level using the `RUST_LOG` environment variable. For example:
```bash
RUST_LOG=info cargo run --release
```

## Limitations
- SSL certificate paths must be correctly configured in `config.yaml`.
- Requires valid certificates for all domains.

## Contributing
Contributions are welcome! Please open an issue or submit a pull request for any bugs or feature requests.

## License
This project is licensed under the MIT License. See the `LICENSE` file for more details.
