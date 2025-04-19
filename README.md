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

- **Harbinger** – Manages API interactions, database logging, and environment-related logging.
- **Gracey** – Handles service shutdowns and sequence-related tasks.
- **Seedey** – Manages seeding processes (A seed is a .sql file that helps you automatically create tables in your database).
- **Algor** – Drives feed recommendations and basic post moderation.

### Setup

1. Compile **Harbinger** for your server and run it.
2. On the first run, it will generate a **config.yaml** and an **openapi.json**. Configure the configuration file; otherwise, it won't work.
3. Ensure all **requirements** are met. If your environment is set to "production," it will check if your server meets the hardware requirements to host Harbinger.
4. Ensure the database is **seeded** correctly. Although Seedey is good at its job, it might doze off sometimes, so double-check!

## Contribution Guidelines

For the current period, we are only allowing bug and vulnerability reports and no direct contributions.

### Contributors

[![Contributors](https://contrib.rocks/image?repo=NetSocialOSS/Harbinger)](https://github.com/NetSocialOSS/API/graphs/contributors)

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=NetSocialOSS/Harbinger&type=Timeline)](https://star-history.com/#NetSocialOSS/Harbinger&Timeline)