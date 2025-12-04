# 🧠 DNS-Based Intrusion Detection System (DNS-IDS)

![Java](https://img.shields.io/badge/Java-17%2B-blue?logo=java)
![Maven](https://img.shields.io/badge/Build-Maven-orange?logo=apachemaven)
![SQLite](https://img.shields.io/badge/Database-SQLite-blue?logo=sqlite)
![Status](https://img.shields.io/badge/Status-In%20Progress-yellow)

---

## 📘 Overview

**DNS-IDS** is a system designed to **detect malicious DNS activity** (such as tunneling or data exfiltration) in real time by analyzing DNS traffic patterns.
This project is part of the **ECS 235 – Computer and Information Security** course at **UC Davis**.

The system:

* Captures DNS queries
* Extracts behavioral features
* Flags anomalies using **statistical thresholds** and **rule-based analysis**

---

## 🎯 Research Question

> How can real-time DNS traffic analysis identify malicious activity such as tunneling or data exfiltration?

We investigate whether anomalies in DNS query patterns — such as:

* High-entropy subdomains
* Unusually long subdomain names
* Repeated NXDOMAIN responses
* Abnormally high query rates per client

can serve as **reliable indicators of attack** without excessive false positives.

---



**Modules:**

1. **DNS Traffic Collector** – Captures DNS queries and stores them for processing.
   *Input:* `.pcap`, `.csv`, or live DNS stream
   *Output Fields:* timestamp, client IP, domain, query type, response code

2. **Feature Extraction Module** – Converts raw logs to numerical features:

   * Query rate per client
   * Domain name length
   * Subdomain entropy
   * NXDOMAIN response ratio

3. **Anomaly Detection Engine** – Uses rule-based and statistical thresholds to flag anomalies.

4. **Alerting & Visualization** – Displays real-time DNS traffic and anomaly alerts.

5. **Reporting Module** – Generates periodic anomaly summary reports.

---

## 🪠 Technology Stack

| Component      | Technology                                                                                                     |
| -------------- | -------------------------------------------------------------------------------------------------------------- |
| **Backend**    | Java 17, Spring Boot 3.5.7, Maven                                                                             |
| **Frontend**   | React 18 (via CDN), HTML5, CSS3                                                                               |
| **Database**   | H2 Database (in-memory)                                                                                        |
| **Libraries**  | Spring Data JPA, Lombok, H2 Database                                                                           |

---

## ⚙️ Setup Instructions

### 1. Prerequisites

Ensure you have:

* **Java 17** (required - Java 25 has compatibility issues)
* **Python 3** (for frontend server)
* **Maven** (optional - project includes Maven Wrapper)

Check Java version:

```bash
java -version
# Should show version 17.x.x
```

If you don't have Java 17, install it:

**macOS (using Homebrew):**
```bash
brew install openjdk@17
export JAVA_HOME=/opt/homebrew/opt/openjdk@17
export PATH="/opt/homebrew/opt/openjdk@17/bin:$PATH"
```

### 2. Clone the Repository

```bash
git clone <repository-url>
cd ecs_235
```

### 3. Build the Backend

```bash
cd DnsIds
./mvnw clean install
```

Or if you have Maven installed globally:

```bash
mvn clean install
```

### 4. Run the Backend (Spring Boot)

**Using Maven Wrapper (Recommended):**

```bash
cd DnsIds
export JAVA_HOME=/opt/homebrew/opt/openjdk@17  # Adjust path if needed
export PATH="/opt/homebrew/opt/openjdk@17/bin:$PATH"
./mvnw spring-boot:run
```

**Or using global Maven:**

```bash
cd DnsIds
mvn spring-boot:run
```

The backend will start on **http://localhost:8081**

### 5. Run the Frontend

Open a **new terminal window** and navigate to the frontend directory:

```bash
cd DnsIds/frontend
python3 -m http.server 3005
```

The frontend will be available at **http://localhost:3005**

**Note:** If port 3005 is in use, you can use any available port (e.g., `python3 -m http.server 3006`)

### 6. Access the Application

1. Open your browser and navigate to: **http://localhost:3005**
2. The DNS-IDS dashboard will load
3. Use the interface to:
   - **Generate Dataset**: Create DNS query data
   - **Run Analysis**: Analyze existing data for threats
   - **Generate & Analyze**: Do both in one action

### 7. Quick Start (Both Servers)

**Terminal 1 - Backend:**
```bash
cd DnsIds
export JAVA_HOME=/opt/homebrew/opt/openjdk@17
export PATH="/opt/homebrew/opt/openjdk@17/bin:$PATH"
./mvnw spring-boot:run
```

**Terminal 2 - Frontend:**
```bash
cd DnsIds/frontend
python3 -m http.server 3005
```

Then open **http://localhost:3005** in your browser.


---

## 💾 Database Setup

The project uses **H2 in-memory database** by default. Data is stored in memory and will be cleared when the application restarts.

To access the H2 Console:
- URL: **http://localhost:8081/h2-console**
- JDBC URL: `jdbc:h2:mem:testdb`
- Username: `sa`
- Password: (leave empty)

## 🔧 Configuration

### Backend Port
Default port is **8081**. To change it, edit:
```
DnsIds/src/main/resources/application.properties
```
Change `server.port=8081` to your desired port.

### Frontend API Configuration
The frontend connects to the backend API. If you change the backend port, update:
```
DnsIds/frontend/app.js
```
Change `const API_BASE_URL = 'http://localhost:8081/api';` to match your backend port.

## 📡 API Endpoints

### Dataset Generation
- **POST** `/api/dataset/generate?queryCount={count}`
  - Generates DNS query data
  - Query parameter: `queryCount` (default: 100)

### Threat Analysis
- **POST** `/api/detection/analysis`
  - Analyzes DNS queries for threats
  - Returns: List of `AttackResponse` objects with detected threats

### Example Response
```json
[
  {
    "attackType": "MULTIPLE_ATTACKS_DETECTED",
    "queriesAnalyzed": 450,
    "threatsDetected": 4,
    "threats": [...],
    "riskScore": 95,
    "severity": "CRITICAL",
    "recommendation": "..."
  }
]
```

## 📁 Project Structure

```
ecs_235/
└── DnsIds/                          # Main project directory
    ├── src/main/java/
    │   └── com/example/DnsIds/
    │       ├── controller/         # REST API endpoints
    │       ├── service/            # Business logic
    │       ├── repository/        # Data access
    │       ├── dto/                # Data transfer objects
    │       └── entity/             # Database entities
    ├── src/main/resources/
    │   └── application.properties  # Configuration
    ├── frontend/                    # Frontend (React)
    │   ├── index.html              # Main HTML file
    │   ├── app.js                  # React components
    │   ├── styles.css              # Styling
    │   └── README.md               # Frontend documentation
    ├── pom.xml                     # Maven dependencies
    └── mvnw                        # Maven wrapper
```

## 🐛 Troubleshooting

### Java Version Issues
If you see compilation errors related to Java version:
- Ensure Java 17 is installed and active
- Set JAVA_HOME: `export JAVA_HOME=/opt/homebrew/opt/openjdk@17`
- Verify: `java -version` should show 17.x.x

### Port Already in Use
If port 8081 or 3005 is already in use:
- Backend: Change `server.port` in `application.properties`
- Frontend: Use a different port: `python3 -m http.server <port>`
- Update frontend `app.js` to match the new backend port

### CORS Errors
The backend has `@CrossOrigin(origins = "*")` enabled, so CORS should work automatically.

### Frontend Not Loading
- Ensure the frontend server is running: `python3 -m http.server 3005`
- Check browser console for errors
- Verify backend is running on the correct port (default: 8081)

---

## 📚 References

This project draws upon research in:

* DNS-based attack vectors and tunneling techniques
* Statistical anomaly detection in network security
* Real-world DNS exfiltration cases (e.g., **Mirai botnet**)

These informed our feature engineering and detection methodology.

---



## 🧾 Summary

The **DNS-IDS** system provides a foundation for **real-time detection** of DNS-based malicious activity using rule-based and statistical analysis.
It can be extended to handle larger datasets, real-world DNS streams, and advanced ML-driven anomaly detection.


---
