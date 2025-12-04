# DNS-IDS Frontend

A modern, responsive web interface for the DNS-Based Intrusion Detection System.

## Features

- 🎨 **Modern UI Design**: Dark theme with gradient accents and smooth animations
- 📊 **Real-time Visualization**: Interactive dashboard showing threat statistics
- 🚨 **Threat Detection**: Visual cards for each detected threat with risk scores
- 📈 **Statistics Dashboard**: Overview cards showing total threats, queries analyzed, and risk metrics
- 💡 **Recommendations**: Actionable security recommendations for each detected attack
- 📱 **Responsive Design**: Works seamlessly on desktop, tablet, and mobile devices

## Getting Started

### Prerequisites

1. Ensure the Spring Boot backend is running on `http://localhost:8080`
2. A modern web browser (Chrome, Firefox, Safari, or Edge)

### Running the Frontend

1. **Simple Method (Recommended)**: 
   - Open `index.html` directly in your web browser
   - Or use a simple HTTP server:
   
   ```bash
   # Using Python 3
   cd frontend
   python3 -m http.server 3000
   
   # Using Node.js (if you have http-server installed)
   npx http-server -p 3000
   ```

2. **Access the Application**:
   - Open your browser and navigate to `http://localhost:3001` (if using a server)
   - Or simply double-click `index.html` to open it directly
   
   **Note**: If port 3000 is in use, the server will automatically use port 3001

### API Configuration

The frontend is configured to connect to the backend API at `http://localhost:8080`. If your backend runs on a different port or host, edit the `API_BASE_URL` constant in `app.js`:

```javascript
const API_BASE_URL = 'http://localhost:8080/api';
```

## Usage

1. **Generate Dataset**: Click "Generate Dataset" to create DNS query data
   - Adjust the query count using the input field (default: 100)
   
2. **Run Analysis**: Click "Run Analysis" to analyze existing DNS queries

3. **Generate & Analyze**: Click "Generate & Analyze" to do both in one action

4. **View Results**: 
   - Statistics cards show overview metrics
   - Threat cards display detailed information about each detected attack
   - Risk scores are visualized with color-coded progress bars
   - Recommendations provide actionable security advice

## Features Breakdown

### Statistics Dashboard
- **Total Threats**: Number of threats detected
- **Queries Analyzed**: Total DNS queries processed
- **Critical Threats**: Count of high-risk threats (risk score ≥ 90)
- **Average Risk Score**: Mean risk score across all threats

### Threat Cards
Each threat card displays:
- Threat type (Random Subdomain Attack, NXDOMAIN Flood, DNS Flooding)
- Source IP address
- Detailed description
- Risk score (0-100)
- Timestamp

### Attack Response Cards
Each attack response includes:
- Attack type and severity badge
- Number of queries analyzed
- Analysis execution time
- List of all detected threats
- Security recommendations

## Color Coding

- **Critical (Red)**: Risk score 90-100
- **High (Orange)**: Risk score 70-89
- **Medium (Yellow)**: Risk score 40-69
- **Low (Green)**: Risk score 0-39

## Browser Compatibility

- Chrome/Edge 90+
- Firefox 88+
- Safari 14+
- Opera 76+

## Troubleshooting

### CORS Errors
If you encounter CORS errors, ensure the backend has `@CrossOrigin(origins = "*")` annotation (which it already has).

### API Connection Issues
- Verify the backend is running: `http://localhost:8080`
- Check browser console for detailed error messages
- Ensure both frontend and backend are on the same network/localhost

### Styling Issues
- Clear browser cache and reload
- Ensure all CSS files are loaded (check Network tab in DevTools)

## Project Structure

```
frontend/
├── index.html      # Main HTML file
├── styles.css      # All styling and responsive design
├── app.js          # React components and API integration
└── README.md       # This file
```

## Technologies Used

- **React 18**: UI framework (via CDN)
- **Font Awesome 6**: Icons
- **Vanilla CSS**: Custom styling with CSS variables
- **Fetch API**: HTTP requests to backend

## Future Enhancements

Potential improvements:
- Real-time updates via WebSocket
- Historical data visualization with charts
- Export functionality for reports
- Filtering and sorting options
- Dark/light theme toggle

