<h2 align='center'>
  <img src="https://cdn.netsocial.app/images/png/netsocial-transparent.png" height='150px' width='150px'/>
  <br> 
</h2>

## Harbinger - We are the Harbinger of your destiny

Harbinger is the core Go-written API for NetSocial’s backend services. It manages key functionalities related to user-API interactions, algorithms, image detection, and more.

### Requirements

- Go version **1.18.4 or higher**.
- Properly configured `config.yaml` for optimal performance.
- Ensure the **`uuid-ossp`** extension is available on your database by running:
    ```sql
    CREATE EXTENSION "uuid-ossp";
    ```
  _This extension is required for generating UUIDs in PostgreSQL._

### Architecture

Harbinger consists of **one main process** and **three assistant processes**:

- **Harbinger** – Manages API interactions, database logging, and environment-related logging. Handles configuration generation, OpenAPI documentation, and orchestrates all assistant processes.
- **Gracey** – Handles graceful service shutdowns, OS signal handling, and sequence-related tasks to ensure safe termination and cleanup.
- **Seedey** – Manages database seeding and migrations. Now also supports **database backup and restore** operations, making it easier to maintain and recover your data. Seedey can automatically detect and apply new `.sql` files, and provides warnings for complex SQL statements.
- **Algor** – Drives feed recommendations and basic post moderation. Integrates with AI models (like Ollama) for content filtering, spam detection, and recommendation logic. Algor can fetch the currently running AI model and version, and supports toggling features like image filtering and mass mention detection.

### Internal Functions & Features

- **Automatic Configuration & OpenAPI Generation:** On first run, Harbinger generates a `config.yaml` and an `openapi.json` reflecting the current API structure.
- **Dynamic Routing:** Uses the Chi router for modular route registration, including admin, user, notification, coterie, authentication, stats, blogs, and partner endpoints.
- **Error Reporting:** Integrates with Discord webhooks for real-time error notifications, with sensitive data redaction.
- **YAML/JSON Parsing:** Custom parsers for configuration and OpenAPI output, supporting nested structures and type reflection.
- **Environment Checks:** In production mode, Harbinger checks server hardware and environment compatibility before starting.
- **Database Object Detection:** Seedey can parse SQL files to identify tables, enums, and indexes, and now supports backup/restore for disaster recovery.
- **AI Integration:** Algor can fetch and log the running AI model and version, and exposes toggles for enabling/disabling moderation features.

### Setup

1. Compile **Harbinger** for your server and run it.
2. On the first run, it will generate a **config.yaml** and an **openapi.json**. Configure the configuration file; otherwise, it won't work.
3. Ensure all **requirements** are met. If your environment is set to "production," it will check if your server meets the hardware requirements to host Harbinger.
4. Ensure the database is **seeded** correctly. Although Seedey is good at its job, it might doze off sometimes, so double-check!
5. For backup and restore, use Seedey's new commands to create and load database backups as needed.

## Contribution Guidelines

For the current period, we are only allowing bug and vulnerability reports and no direct contributions.

### Contributors

[![Contributors](https://contrib.rocks/image?repo=NetSocialOSS/Harbinger)](https://github.com/NetSocialOSS/API/graphs/contributors)

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=NetSocialOSS/Harbinger&type=Timeline)](https://star-history.com/#NetSocialOSS/Harbinger&Timeline)