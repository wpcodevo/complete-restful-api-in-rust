## 1. Building a Rust API with Unit Testing in Mind

In this article, you will learn how to build a Rust API with unit testing in mind. This means we will take a modular approach, which will make our lives easier when writing unit tests.

![Building a Rust API with Unit Testing in Mind](https://codevoweb.com/wp-content/uploads/2023/08/Building-a-Rust-API-with-Unit-Testing-in-Mind.webp)

### Topics Covered

- Prerequisites
- Running the Rust API Project in Docker
- Running the Rust API Project on Your Machine
- Setting Up the Rust API Project
- Setting Up PostgreSQL and pgAdmin with Docker
- Performing Database Migrations with SQLx-CLI
    - Defining the Database Model
    - Creating the Database Schema
    - Running the Migrations
- Loading the Environment Variables
- Connecting the Rust App to the PostgreSQL Database
- Handling API Errors
- Creating Data Transfer Objects (DTOs)
- Creating Utility Functions
    - Hashing and Comparing Passwords
    - Signing and Verifying JWTs
- Creating the Database Access Layer
- Creating the Authentication Middleware Guard
- Creating Authentication Endpoint Handlers
    - User Registration `/api/auth/register`
    - User Login `/api/auth/login`
    - User Logout `/api/auth/logout`
- Creating Users Endpoint Handlers
    - Retrieve the User Account `/api/users/me`
    - Retrieve a List of Users `/api/users`
- Adding CORS Middleware and Registering API Routes
- Conclusion


Read the entire article here: [https://codevoweb.com/building-a-rust-api-with-unit-testing-in-mind/](https://codevoweb.com/building-a-rust-api-with-unit-testing-in-mind/)

## 2. How to Add Swagger UI, Redoc and RapiDoc to a Rust API

In this article, you will learn how to integrate Swagger UI, Redoc, and RapiDoc into a Rust API project. Yes, we will be generating three documentation UIs, but don't worry, the process is straightforward, and we won't need to write the OpenAPI YAML or JSON configurations manually. 

![How to Add Swagger UI, Redoc and RapiDoc to a Rust API](https://codevoweb.com/wp-content/uploads/2023/08/How-to-Add-Swagger-UI-Redoc-and-RapiDoc-to-a-Rust-API.webp)

### Topics Covered

- Running the Rust API Project in Docker
- Running the Rust API Project on Your Machine
- Installing the Utopia Swagger Ui Crates
- Adding SwaggerUi to the Rust API
  - Registering the OpenAPI Schema
  - Registering the API Handler as OpenAPI Path
  - Generating the OpenApi Base Object
  - Serving the Swagger Ui via a Web Server
  - The Complete Code
- Passing JWT Bearer Token in Swagger Ui
- Registering All the DTOs as OpenAPI Schemas
- Registering the Authentication API Handlers as OpenAPI Paths
- Registering the User-Related Handlers as OpenAPI Paths
- Generating the OpenAPI Object and Serving the Swagger Ui
- Adding Redoc and Rapidoc to the API
- Conclusion
  
Read the entire article here: [https://codevoweb.com/add-swagger-ui-redoc-and-rapidoc-to-a-rust-api/](https://codevoweb.com/add-swagger-ui-redoc-and-rapidoc-to-a-rust-api/)

