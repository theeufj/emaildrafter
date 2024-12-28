# EmailDrafter

EmailDrafter is an automated email drafting tool that integrates with your Gmail account. It scans your inbox for new emails and drafts responses based on your historical communication style. Additionally, it can recommend meeting times if someone requests a meeting.

## Features

- **Automated Email Drafting**: Automatically drafts responses to emails in your Gmail inbox.
- **Meeting Time Recommendations**: Suggests available meeting times based on your calendar when a meeting is requested.
- **Persona-Based Responses**: Crafts responses that reflect your professional persona and communication style.

## Project Structure

## Getting Started

### Prerequisites

- Docker
- Docker Compose
- Go 1.17 or later

### Installation

1. **Clone the repository**:
    ```sh
    git clone https://github.com/yourusername/emaildrafter.git
    cd emaildrafter
    ```

2. **Set up environment variables**:
    Create a [.env](http://_vscodecontentref_/18) file in the root directory and add your environment variables:
    ```env
    GOOGLE_CLIENT_ID=your-google-client-id
    GOOGLE_CLIENT_SECRET=your-google-client-secret
    GOOGLE_REDIRECT_URI=your-google-redirect-uri
    GEMINI_API_KEY=your-gemini-api-key
    ```

3. **Build and run the application**:
    ```sh
    docker-compose up --build
    ```

### Usage

1. **Authenticate with Google**:
    - Navigate to `http://localhost:8080` and log in with your Google account.

2. **Automatic Email Drafting**:
    - The application will automatically scan your Gmail inbox for new emails and draft responses.

3. **Meeting Time Recommendations**:
    - If an email requests a meeting, the application will suggest available meeting times based on your calendar.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the MIT License.