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

## 3. JWT Authentication and Authorization in Rust API using Actix-Web

In this article, you will learn how to implement JWT Authentication and Authorization in Rust using Actix-Web extractors (middleware).

![JWT Authentication and Authorization in Rust API using Actix-Web](https://codevoweb.com/wp-content/uploads/2023/08/JWT-Authentication-and-Authorization-in-Rust-API-using-Actix-Web.webp)

### Topics Covered

- Middleware Example in TypeScript
  - Authentication Middleware Guard
  - Authorization Middleware Guard
- Understanding How Middleware Works in Actix-Web
  - Exploring the Service Trait
  - Exploring the Transform Trait
- Signing and Verifying JSON Web Tokens (JWTs)
- Creating a JWT Middleware using Actix-Web Extractor
  - Creating the Middleware
  - Creating a Middleware Factory
  - Using the Middleware Factory
  - Writing Unit Tests for the JWT Middleware
- Adding JWT Authorization to the Actix-Web Middleware
  - Modifying the Authentication Middleware
  - Modifying the Middleware Factory
  - Using the Middleware Factory
  - Writing Unit Tests for the Authorization Logic
- Retrieving the User Information
  - Using Only the Request Extension
  - Using an Actix-Web Extractor
- Conclusion
  
  
Read the entire article here: [https://codevoweb.com/jwt-authentication-and-authorization-in-rust-api/](https://codevoweb.com/jwt-authentication-and-authorization-in-rust-api/)

## 4. How to Write Unit Tests for Your Rust API

In this article, you will learn how to write unit tests for your Rust API project using the Actix-web framework and the SQLx toolkit. It's crucial to note that these tests are tailored specifically for the Rust API we've been creating in this tutorial series.

![How to Write Unit Tests for Your Rust API](https://codevoweb.com/wp-content/uploads/2023/08/How-to-Write-Unit-Tests-for-Your-Rust-API.webp)

### Topics Covered

- Running the Unit Tests on Your Machine
- What are Unit Tests?
- Why Should We Perform Unit Testing on Our API?
- Writing Unit Tests for the JWT Utility Functions
- Writing Unit Tests for the Password Utility Functions
- Creating Stubs
- Writing Unit Tests for the Database Access Layer
- Writing Unit Tests for the Middleware Guard
- Writing Unit Tests for the Authentication Handlers
- Writing Unit Tests for the User-Related Handlers
- Conclusion
  
Read the entire article here: [https://codevoweb.com/how-to-write-unit-tests-for-your-rust-api/](https://codevoweb.com/how-to-write-unit-tests-for-your-rust-api/)

## 5. Dockerizing a Rust API Project, SQL Database, and pgAdmin

In this article, we'll be dockerizing our Rust API project within our development environment.

![Dockerizing a Rust API Project, SQL Database and pgAdmin](https://codevoweb.com/wp-content/uploads/2023/09/Dockerizing-a-Rust-API-Project-SQL-Database-and-pgAdmin.webp)

### Topics Covered

- Requirements
- Running the Rust API Project in Docker
- Running the Rust API Project on Your Machine
- What is Docker Compose?
- Setting Up Rust API with Docker Support
- Configuring PostgreSQL and pgAdmin Containers with Docker Compose
   - Setting PostgreSQL and pgAdmin Ports for Development
- Generating the SQLx Prepared Queries
- Configuring Rust API Container with Docker Compose
   - Setting Up Dockerfile for the Rust Project
   - Setting Up Docker Compose for the Rust API
   - Setting Container Port and Database URL for Development
- Running the Rust API with Docker Compose
- Testing the Rust API using Swagger Docs
- Accessing the pgAdmin Container from your Browser
- Conclusion

  
Read the entire article here: [https://codevoweb.com/dockerizing-a-rust-api-project/](https://codevoweb.com/dockerizing-a-rust-api-project/)


