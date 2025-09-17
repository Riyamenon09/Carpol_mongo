Andaman RideShare 🚗🌴

A full-stack carpooling platform built for the Andaman Islands, allowing users to find, share, and book rides in a seamless way.
The platform is designed to connect drivers with available seats to passengers heading in the same direction, reducing travel costs and promoting sustainable shared travel.

Built with a Flask (Python) backend, MongoDB database, and a Bootstrap-powered responsive frontend, it integrates REST APIs for ride search and autocomplete, along with secure user authentication.

✨ Features
🔑 Authentication & Security

User registration and login with password hashing (Werkzeug)

Session management to keep users logged in securely

Protection against invalid inputs and unauthorized access

🚗 Ride Management

Drivers can post rides with origin, destination, available seats, and price per person

Passengers can search and book rides based on location and number of passengers

Automatic seat availability updates after booking

🔎 Smart Search & Autocomplete

REST API endpoints to fetch available places and rides

Real-time autocomplete suggestions while typing pickup/destination

Search filtering by passenger count and optional female drivers only filter

💻 Responsive Frontend

Built with HTML, CSS, JavaScript, Bootstrap for a clean user experience

Fully responsive design optimized for desktop and mobile devices

Modern UI with form validation, autocomplete dropdowns, and dynamic redirects

📊 Database & Data Handling

MongoDB collections for users, rides, and bookings

Flexible schema to store driver details, ride info, pricing, and status

Queries optimized with filters for seats, gender, origin, and destination

🛠️ Tech Stack

Backend: Flask (Python), REST API

Database: MongoDB (NoSQL, document-oriented)

Frontend: HTML, CSS, JavaScript, Bootstrap (responsive UI)

Authentication: Werkzeug (password hashing), Flask session management

Other Tools:

PyMongo for database connectivity

dotenv for environment variable management

Jinja2 templating engine for dynamic HTML rendering
