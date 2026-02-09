## Secure Cloud User Authentication System

This is a simple but secure Flask + SQLite project, designed for a BCA final-year student to demonstrate:

- Password hashing with Werkzeug (PBKDF2 + SHA-256)
- Session-based authentication with secure cookies
- CSRF protection for all forms
- Brute-force login protection
- Role-Based Access Control (user vs admin)
- Basic security headers and XSS protection
- **Admin:** Create users, delete users, change roles
- **User profile:** Edit email, change password
- **User dashboard & Admin dashboard** with stats

### Project Structure

- `app.py` – main Flask application and routes
- `secure_auth.db` – SQLite database (auto-created on first run)
- `Dockerfile` – Docker image definition
- `docker-compose.yml` – Docker Compose configuration
- `static/` – Static files (add `logo.png` here for your custom logo)
- `templates/` – HTML templates
  - `base.html`
  - `login.html`
  - `register.html`
  - `user_dashboard.html`
  - `admin_dashboard.html`
  - `profile.html`
- `requirements.txt` – Python dependencies

### How to Run Locally

1. **Go to the project folder**

```bash
cd secure-cloud-auth
```

2. **Create a virtual environment (recommended)**

```bash
python3 -m venv venv
source venv/bin/activate      # On Windows: venv\Scripts\activate
```

3. **Install dependencies**

```bash
pip install -r requirements.txt
```

4. **Run the Flask app**

```bash
python app.py
```

5. **Open in browser**

Go to `http://127.0.0.1:5000` (or the Network URL printed in the terminal)

### Share with Classmates (Same WiFi)

The app runs on `0.0.0.0` by default, so others on your network can access it:

1. Run the app: `python app.py`
2. Check the terminal—it prints a **Network URL** like `http://192.168.1.x:5000`
3. Share that URL with classmates on the same WiFi
4. They can register and log in from their devices

**Tip:** If the Network URL doesn't work, find your IP:
- Linux/Mac: `hostname -I` or `ip addr`
- Windows: `ipconfig`

**Share beyond WiFi?** Deploy to [Railway](https://railway.app), [Render](https://render.com), or [PythonAnywhere](https://pythonanywhere.com) for a public URL.

### How to Run with Docker

**Using Docker Compose (recommended):**

```bash
docker compose up --build
```

Then open `http://localhost:5000` in your browser.

**Using Docker directly:**

```bash
docker build -t secure-cloud-auth .
docker run -p 5000:5000 -v auth_data:/data -e DATABASE=/data/secure_auth.db secure-cloud-auth
```

To set a custom `SECRET_KEY` for production: `-e SECRET_KEY=your-secret-key`

### Demo Admin Account

On first run, a default admin user is created automatically:

- **Username:** `admin`
- **Password:** `Admin@123`

- or using cloud Access
# cloudflared tunnel --url http://localhost:5000


Use this to access the admin dashboard and manage users.

### Features

| Feature | Description |
|---------|-------------|
| **Admin dashboard** | View all users, stats (total, admins, users) |
| **Create user** | Admin can create users with username, email, password, role |
| **Delete user** | Admin can delete any user (except self) |
| **Change role** | Admin can promote/demote users (admin ↔ user) |
| **Profile** | Edit email, change password (requires current password) |
| **Profile avatar** | Initial-based avatar on profile page |

