# TTKServer

This is a Rust-based server application.

## Getting Started

To get a local copy up and running, follow these simple steps.

### Prerequisites

*   [Rust](https://www.rust-lang.org/tools/install)

### Installation

1.  Clone the repo
    ```sh
    git clone https://github.com/your_username/TTKServer.git
    ```
2.  Build the project
    ```sh
    cargo build --release
    ```

## Usage

To run the server, use the following command:

```sh
cargo run --release
```

## Running Tests

To run the test suite, use the following command:

```sh
cargo test
```

## CI/CD

This project uses GitHub Actions for CI/CD:

*   **Main Workflow (`main.yml`):** Triggered on pushes to the `main` branch. This workflow builds the Docker image, bumps the version in `Cargo.toml`, and pushes the image to Amazon ECR with `latest` and version tags.
*   **Test and Lint Workflow (`test-and-lint.yml`):** Triggered on pushes to any branch except `main`. This workflow runs tests and lints the code, automatically committing any formatting changes.

## Docker

This project includes a `Dockerfile` to build a containerized version of the application. The CI/CD pipeline automatically builds and pushes the image to a private ECR repository.
