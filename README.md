# Online Secure Student Information System

This repository contains the project files for the **Online Secure Student Information System** developed for `CSEC 3352 Secure Software Engineering` at Prince Mohammad Bin Fahd University.

## Overview

This project is a small web-based student information system built with security as a main focus. It demonstrates how a simple academic system can apply secure software engineering practices to protect user accounts, grades, and access to student data.

## Features
- Input validation for usernames, passwords, and grades
- Student account creation
- Secure login with hashed passwords
- Role-based access control for students and instructors
- Instructor-only grade posting
- Student-only access to personal grades
- Password update functionality
- Login attempt tracking and basic brute-force mitigation
- Activity logging for important security-related events

## Implementation

The application is implemented in Python using the Flask framework. User and grade data are stored in an SQLite database.

## How It Works

When the application starts, it initializes the database and creates default records if they do not already exist. A user can then create a student account or log in through the main page.

After login, the system checks the user role:

- Instructors are redirected to the grade management page, where they can add or update student grades.
- Students are redirected to the grade viewing page, where they can only view their own grades.

## Repository Contents

- `app.py` - main application file
- `database.db` - project database
- `app.log` - log files that demonstrate testing
