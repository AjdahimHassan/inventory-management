# Inventory Management System

A web-based inventory management system built with Flask and MongoDB.

## Features

- User authentication and authorization
- Inventory tracking
- Sales management
- Marketplace integration
- Bilingual support (English/French)
- Responsive design

## Tech Stack

- Backend: Flask
- Database: MongoDB
- Frontend: Bootstrap 5
- Authentication: Flask-Login
- Deployment: Render

## Local Development Setup

1. Clone the repository:
```bash
git clone https://github.com/YOUR_USERNAME/inventory-management.git
cd inventory-management
```

2. Create and activate virtual environment:
```bash
python -m venv venv
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create `.env` file:
```
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=your-secret-key-here
MONGODB_URI=your_mongodb_connection_string
MONGODB_DB=inventory_db
```

5. Run the application:
```bash
flask run
```

## Deployment

1. Set up MongoDB Atlas:
   - Create a free account
   - Create a new cluster
   - Set up database user
   - Get connection string

2. Deploy on Render:
   - Create a free account
   - Create new Web Service
   - Connect GitHub repository
   - Add environment variables
   - Deploy

## Environment Variables

- `FLASK_APP`: Application entry point
- `FLASK_ENV`: Development/Production environment
- `SECRET_KEY`: Flask secret key
- `MONGODB_URI`: MongoDB connection string
- `MONGODB_DB`: Database name

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License. 