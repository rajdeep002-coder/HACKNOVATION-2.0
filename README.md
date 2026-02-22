# HACKNOVATION-2.0
NeuralShield
Intelligent Web Application Firewall (WAF)
->Overview

NeuralShield is a full-stack Web Application Firewall designed to detect and block common web attacks such as SQL Injection (SQLi) and Cross-Site Scripting (XSS) in real time.

The system analyzes HTTP requests, classifies threats based on severity and confidence score, stores logs securely, and provides a centralized dashboard for monitoring and analytics.

-> Problem Statement

Modern web applications are vulnerable to SQL Injection and XSS attacks.
Small and Medium Enterprises (SMEs) often lack affordable and easy-to-deploy web security solutions.

There is a need for a scalable, real-time, and developer-friendly protection system.

-> Key Features

Real-time SQL Injection detection

Real-time XSS detection

Automatic malicious request blocking

Severity classification (Low, Medium, High, Critical)

Confidence score calculation

Secure attack log storage (PostgreSQL)

Dashboard analytics using charts

Admin authentication system

Log export functionality

->System Architecture

NeuralShield follows a three-tier architecture:

1️⃣ Presentation Layer

Admin Dashboard

Scanner Interface

Attack Logs View

Analytics Charts

2️⃣ Application Layer

Spring Boot Backend

Rule-based WAF Detection Engine

Business Logic Processing

3️⃣ Data Layer

PostgreSQL Database

Attack Log Storage

Authentication Data

🛠 Technologies Used
Frontend

HTML

CSS

JavaScript

Chart.js

Backend

Java

Spring Boot

Database

PostgreSQL

Tools

IntelliJ IDEA

Git & GitHub

-> How It Works

User submits an HTTP request.

The WAF engine analyzes the request using predefined detection rules.

If malicious patterns are found:

The request is blocked.

Severity and confidence are calculated.

The attack is logged in PostgreSQL.

Dashboard updates with real-time statistics.

-> Future Scope

Machine learning-based anomaly detection

IP tracking and rate limiting

Bot detection system

Cloud-based SaaS deployment

Multi-tenant architecture

-> Project Presentation

You can download the project presentation here:

Download NeuralShield PPT

-> Viva Documentation

Detailed viva file available here:

View Viva File

-> Conclusion

NeuralShield transforms web security from passive logging into proactive protection.
It provides real-time detection, automatic blocking, and centralized monitoring in a scalable and affordable architecture.
