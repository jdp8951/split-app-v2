# SplitApp

SplitApp is a Spring Boot-based expense splitting application that allows users to create groups, add expenses, split bills, and settle balances easily.

## Features

- **User Authentication (JWT-based):**
  - Secure login and registration endpoints.
  - Uses JSON Web Tokens for stateless authentication.
  - Protects sensitive API endpoints so only authenticated users can access them.

- **Group and Expense Management:**
  - Create and manage groups for splitting expenses.
  - Add, edit, and delete expenses within groups.
  - Assign expenses to one or more users in a group.

- **Equal Expense Splitting Among Group Members:**
  - Automatically calculates each member's share when an expense is added.
  - Supports adding/removing members from expenses and recalculates shares accordingly.
  - Ensures the payer can also be included in the split.

- **Settlement Calculation and Tracking:**
  - Computes how much each user owes or is owed within a group.
  - Generates a minimal set of transactions to settle up all debts.
  - Provides endpoints to view balances and record settlements.

- **RESTful API Endpoints:**
  - Well-structured endpoints for all major operations (users, groups, expenses, settlements).
  - Follows REST conventions for easy integration with frontend or mobile apps.

- **PostgreSQL Database Integration:**
  - Stores all user, group, expense, and settlement data in a reliable relational database.
  - Supports both local and cloud-hosted PostgreSQL instances.

## Database Information

- **Database:** PostgreSQL
- **Default Port:** 5432
- **Recommended Version:** 12 or above
- **Sample connection properties:**
  ```
  spring.datasource.url=jdbc:postgresql://<host>:5432/<database>
  spring.datasource.username=<your_db_username>
  spring.datasource.password=<your_db_password>
  spring.datasource.driver-class-name=org.postgresql.Driver
  spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
  ```
- You can use a local PostgreSQL instance or a managed service (Railway, Render, AWS RDS, etc.).
- **Important:** Never commit your real credentials to version control.

## Setup Instructions

1. Clone the repository:
   ```bash
   git clone https://github.com/rohitshimpi737/splitapp.git
   cd splitapp
   ```
2. Configure the Database:
    - Create a PostgreSQL database (locally or using a cloud provider like Railway, Render, or AWS).
    - Update `src/main/resources/application-dev.properties` with your database credentials.
    - **Important:** Do not commit sensitive files. Add `application-dev.properties` to your `.gitignore`.
3. Build the Project:
   ```bash
   mvn clean install
   ```
4. Configure the database connection in `src/main/resources/application.properties`.
5. Run the application:
   ```bash
   mvn spring-boot:run
   ```
6. Access the application at `http://localhost:8080`.

## **Postman Collection**

You can import the provided Postman collection file for ready-to-use requests and testing:

[SplitApp-API.postman_collection.json on GitHub Gist](https://gist.github.com/rohitshimpi737/573c9b6802b8b9ff0d531f9b9d67d332)

---

## API Usage

# SplitApp API Documentation

This document describes the available API endpoints for the SplitApp backend.  
**Base URL:** `https://split-app-production-5538.up.railway.app`

---

## Authentication

### **Register New User**
- **POST** `/api/v1/user/register`
- **Body (JSON):**
  ```json
  {
    "username": "Rohit",
    "email": "Rohit@example.com",
    "phone": {
      "countryCode": "+91",
      "phoneNumber": 7020910075
    },
    "password": "password123"
  }
  ```
- **Response:** User registration confirmation.

---

### **Login User**
- **POST** `/api/v1/auth/login`
- **Body (JSON):**
  ```json
  {
    "userEmail": "jigar@gmail.com",
    "password": "12345678"
  }
  ```
- **Response:**
  ```json
  {
    "accessToken": "<JWT_TOKEN>",
    "refreshToken": "<REFRESH_TOKEN>"
  }
  ```
- **Note:** Use the `accessToken` for all protected endpoints as a Bearer token.

---

### **Refresh Token**
- **POST** `/api/v1/auth/refresh_token`
- **Body (JSON):**
  ```json
  {
    "refreshToken": "<REFRESH_TOKEN>"
  }
  ```
- **Response:** New access token.

---

## User

### **Get User**
- **GET** `/api/v1/user`
- **Headers:**  
  `Authorization: Bearer <accessToken>`
- **Response:** User details.

### **Update User**
- **PUT** `/api/v1/user/update`
- **Headers:**  
  `Authorization: Bearer <accessToken>`
- **Body (JSON):**
  ```json
  {
    "username": "satwik",
    "email": "satwik@gmail.com",
    "phone": {
      "countryCode": "+91",
      "phoneNumber": 9999999999
    },
    "password": "fun123"
  }
  ```
- **Response:** Updated user details.

### **Delete User**
- **DELETE** `/api/v1/user/delete`
- **Headers:**  
  `Authorization: Bearer <accessToken>`
- **Response:** Deletion confirmation.

---

## Group

### **Create Group**
- **POST** `/api/v1/group/create`
- **Headers:**  
  `Authorization: Bearer <accessToken>`
- **Body (JSON):**
  ```json
  {
    "groupName": "Flatmates"
  }
  ```
- **Response:** Group creation confirmation.

### **Add Member to Group**
- **POST** `/api/v1/group/add-member/{groupId}?memberId={memberId}`
- **Headers:**  
  `Authorization: Bearer <accessToken>`
- **Response:** Member addition confirmation.

### **Update Group**
- **PUT** `/api/v1/group/update/{groupId}`
- **Headers:**  
  `Authorization: Bearer <accessToken>`
- **Body (JSON):**
  ```json
  {
    "groupName": "hello group"
  }
  ```
- **Response:** Updated group details.

### **Get All Groups of User**
- **GET** `/api/v1/group`
- **Headers:**  
  `Authorization: Bearer <accessToken>`
- **Response:** List of groups.

### **Get Group Details**
- **GET** `/api/v1/group/{groupId}`
- **Headers:**  
  `Authorization: Bearer <accessToken>`
- **Response:** Group details.

### **Get Members of a Group**
- **GET** `/api/v1/group/{groupId}/members`
- **Headers:**  
  `Authorization: Bearer <accessToken>`
- **Response:** List of group members.

### **Delete Group**
- **DELETE** `/api/v1/group/delete?groupId={groupId}`
- **Headers:**  
  `Authorization: Bearer <accessToken>`
- **Response:** Group deletion confirmation.

### **Delete Member from Group**
- **DELETE** `/api/v1/group/remove-member/{memberId}`
- **Headers:**  
  `Authorization: Bearer <accessToken>`
- **Response:** Member removal confirmation.

---

## Expenses

### **Create Non-grouped Expense**
- **POST** `/api/v1/expense/create`
- **Headers:**  
  `Authorization: Bearer <accessToken>`
- **Body (JSON):**
  ```json
  {
    "amount": 123.00,
    "description": "This is bar type expense"
  }
  ```
- **Response:** Expense creation confirmation.

### **Create Grouped Expense**
- **POST** `/api/v1/expense/create/{groupId}`
- **Headers:**  
  `Authorization: Bearer <accessToken>`
- **Body (JSON):**
  ```json
  {
    "amount": 1000.00,
    "description": "Dinner."
  }
  ```
- **Response:** Expense creation confirmation.

### **Add Ower to Expense**
- **POST** `/api/v1/expense/add-ower/{expenseId}?owerId={owerId}`
- **Headers:**  
  `Authorization: Bearer <accessToken>`
- **Response:** Ower addition confirmation.

### **Get Expense**
- **GET** `/api/v1/expense/{expenseId}`
- **Headers:**  
  `Authorization: Bearer <accessToken>`
- **Response:** Expense details.

### **Get Expenses of Group**
- **GET** `/api/v1/expense/group/{groupId}`
- **Headers:**  
  `Authorization: Bearer <accessToken>`
- **Response:** List of expenses for the group.

### **Delete Expense**
- **DELETE** `/api/v1/expense/delete/{expenseId}`
- **Headers:**  
  `Authorization: Bearer <accessToken>`
- **Response:** Expense deletion confirmation.

### **Remove Payer**
- **DELETE** `/api/v1/expense/remove-payer/{expenseId}?payerId={payerId}`
- **Headers:**  
  `Authorization: Bearer <accessToken>`
- **Response:** Payer removal confirmation.

---

## Report

### **Get Full Report**
- **GET** `/api/v1/report/{groupId}`
- **Headers:**  
  `Authorization: Bearer <accessToken>`
- **Response:** Group report.

### **Export Report**
- **GET** `/api/v1/report/{groupId}/export?fileType=XLSX`
- **Headers:**  
  `Authorization: Bearer <accessToken>`
- **Response:** Downloadable report file.

---

## Settlement

### **Calculate Settlement**
- **GET** `/api/v1/settlement/group/{groupId}`
- **Headers:**  
  `Authorization: Bearer <accessToken>`
- **Response:** List of settlement transactions.

### **Check User Balances**
- **GET** `/api/v1/settlement/group/{groupId}/balances`
- **Headers:**  
  `Authorization: Bearer <accessToken>`
- **Response:** List of user balances in the group.

---

## **Authentication**

For all protected endpoints, include the following header:
```
Authorization: Bearer <accessToken>
```
Obtain the `accessToken` by logging in via `/api/v1/auth/login`.

---

## Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

## License

[MIT](LICENSE)"# split-app-v2" 
