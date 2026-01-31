# User Authentication System (MERN Stack)

## Project Description

This project is a full-stack User Authentication System developed using the MERN stack.
It allows users to register, log in securely, and access a protected page after authentication.
Passwords are encrypted using bcrypt before storing them in MongoDB, and JWT is used for secure authorization.

The main objective of this project is to demonstrate user authentication and authorization in a MERN stack application.

---

## Technologies Used

* React JS (Frontend)
* UI Components:shadcn/ui (Radix UI + Tailwind CSS)
* Node.js
* Express.js
* MongoDB Atlas
* Mongoose
* bcrypt (Password Encryption)
* JSON Web Token (JWT)

---

## Features

* User Registration
* User Login
* Password Encryption using bcrypt
* JWT-based Authentication
* Protected Route (Access Granted after login)
* Update User Profile
* Delete User Account
* Basic Frontend Form Validation

---

## Project Structure

```
frontend/   → React frontend  
backend/    → Node.js & Express backend  
```

---

## Steps to Run the Project Locally

### Backend Setup

1. Navigate to backend folder:

```
cd backend
```

2. Install dependencies:

```
npm install
```

3. Create a `.env` file inside the backend folder and add:

```
MONGO_URI=your_mongodb_connection_string
JWT_SECRET=your_secret_key
```

4. Start the backend server:

```
node server.js
```

Backend will run on:

```
http://localhost:5000
```

---

### Frontend Setup

1. Navigate to frontend folder:

```
cd frontend
```

2. Install dependencies:

```
npm install
```

3. Start the frontend:

```
npm start
```

Frontend will run on:

```
http://localhost:3000
```

---

## Application Flow

1. User registers with name, email, and password
2. Password is encrypted and stored in MongoDB
3. User logs in using email and password
4. JWT token is generated and stored in localStorage
5. User is redirected to a protected page displaying “Access Granted”
6. Authenticated user can update or delete their account
7. User can log out securely

---

## CRUD Operations Implemented

* Create: User Registration
* Read: Login and Protected Route Access
* Update: Update User Profile
* Delete: Delete User Account

---

## Conclusion

This project successfully implements a secure User Authentication System using the MERN stack.
It demonstrates full-stack interaction, encrypted password storage, JWT-based authorization, protected routes, and complete CRUD operations while following all given project constraints.
