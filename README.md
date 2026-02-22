# HACKNOVATION-2.0
NeuralShield

Intelligent Web Application Firewall (WAF)

1. Project Overview

NeuralShield is a full-stack Web Application Firewall designed to protect web applications from common web-based attacks such as SQL Injection (SQLi) and Cross-Site Scripting (XSS).

The system analyzes incoming HTTP requests in real time, detects malicious patterns using a rule-based detection engine, blocks harmful requests, and stores detailed logs in a PostgreSQL database.

It provides a centralized administrative dashboard for monitoring, analytics, and attack history management.

2. Problem Statement

Web applications are one of the most targeted components in modern software systems. Attacks such as SQL Injection and Cross-Site Scripting can lead to:

Unauthorized database access

Data breaches

Website defacement

Financial and reputational damage

Many small and medium-scale organizations lack affordable and easy-to-deploy security solutions. Enterprise-grade Web Application Firewalls are often expensive and complex to configure.

There is a need for a practical, scalable, and cost-effective web security solution that provides real-time protection and centralized monitoring.

3. Objectives

The primary objectives of NeuralShield are:

To detect malicious HTTP requests targeting web applications

To automatically block SQL Injection and XSS attacks

To classify detected threats based on severity levels

To calculate a confidence score for each detected attack

To store structured attack logs in a secure database

To provide a real-time analytics dashboard for administrators

4. System Architecture

NeuralShield follows a three-tier architecture to ensure modularity and scalability.

4.1 Presentation Layer

The presentation layer consists of:

Admin login interface

Security scanner page

Attack logs page

Analytics dashboard with charts

This layer is developed using HTML, CSS, and JavaScript, with Chart.js used for visual analytics.

4.2 Application Layer

The application layer is implemented using Spring Boot and contains:

REST controllers for handling requests

Rule-based WAF detection engine

Business logic processing

Attack classification and logging mechanism

This layer is responsible for analyzing requests and managing system logic.

4.3 Data Layer

The data layer uses PostgreSQL for persistent storage. It stores:

Attack logs

Severity levels

Confidence scores

Timestamps

User authentication data

5. Technologies Used

Frontend:

HTML

CSS

JavaScript

Chart.js

Backend:

Java

Spring Boot

Database:

PostgreSQL

Development Tools:

IntelliJ IDEA

Git and GitHub

6. Implemented Features

NeuralShield currently includes the following implemented features:

Real-time SQL Injection detection

Real-time XSS detection

Rule-based pattern matching engine

Automatic blocking of malicious requests

Severity classification (Low, Medium, High, Critical)

Confidence score calculation

Secure storage of attack logs

Dashboard-based analytics and visualization

Admin authentication system

Log export functionality

7. Working Mechanism

An HTTP request is submitted to the system.

The Spring Boot backend forwards the request to the WAF detection engine.

The detection engine evaluates the request using predefined attack patterns.

If malicious content is detected:

The request is blocked.

Severity level is assigned.

Confidence score is calculated.

Attack details are stored in PostgreSQL.

The dashboard updates in real time to reflect new attack data.

8. Advantages of the System

Provides real-time web attack detection

Offers automatic blocking instead of passive logging

Ensures centralized monitoring

Maintains structured and searchable attack logs

Designed with scalable architecture

Suitable for small and medium-scale applications

9. Future Enhancements

Planned future improvements include:

Machine learning-based anomaly detection

IP tracking and reputation analysis

Rate limiting and bot detection

Cloud-based SaaS deployment

Multi-tenant enterprise architecture

10. Conclusion

NeuralShield is a scalable and practical Web Application Firewall that provides real-time detection and blocking of common web attacks.

By combining rule-based detection, structured logging, and centralized analytics, it offers a secure and manageable solution for web application protection. The modular architecture allows future enhancements and scalability.
