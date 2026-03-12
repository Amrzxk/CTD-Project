# Cyber Threat Detection Dashboard

AI-powered real-time network anomaly detection dashboard built with React 18+ and modern web technologies.

![Cyber Threat Detection Dashboard](https://via.placeholder.com/1200x600/0a0a0f/00ff88?text=Cyber+Threat+Detection+Dashboard)

## 🚀 Features

### Core Functionality
- **Batch Analysis**: Upload CSV files for comprehensive network traffic analysis
- **Manual Input**: Real-time threat detection for individual connections
- **Results Dashboard**: View, filter, and export prediction results
- **Analytics & Visualization**: Interactive charts and statistics
- **Alert System**: Real-time notifications for critical threats

### Technical Features
- ✅ React 18+ with functional components and hooks
- ✅ React Router for navigation with lazy loading
- ✅ React Hook Form for form management with validation
- ✅ Recharts for data visualization
- ✅ Tailwind CSS for styling
- ✅ TypeScript for type safety
- ✅ Motion (Framer Motion) for animations
- ✅ Sonner for toast notifications
- ✅ Responsive design (mobile, tablet, desktop)
- ✅ Dark theme with cybersecurity aesthetic
- ✅ Keyboard shortcuts (Ctrl+U for upload, Ctrl+M for manual)

## 🎨 Design

The dashboard features a modern cybersecurity theme with:
- **Primary Color**: Neon Green (#00ff88) - for success and safe operations
- **Secondary Color**: Cyan Blue (#00ccff) - for information and actions
- **Danger Color**: Red (#ff3366) - for threats and malicious activity
- **Background**: Dark gradient (gray-900 to black)

## 📁 Project Structure

```
src/
├── app/
│   ├── components/
│   │   ├── ui/              # Reusable UI components
│   │   ├── Navigation.tsx   # Top navigation bar
│   │   └── AlertBanner.tsx  # Critical alert banner
│   ├── pages/
│   │   ├── LandingPage.tsx      # Home page
│   │   ├── UploadPage.tsx       # CSV upload & batch processing
│   │   ├── ManualInputPage.tsx  # Manual threat analysis
│   │   ├── DashboardPage.tsx    # Results table with filters
│   │   └── AnalyticsPage.tsx    # Charts and statistics
│   ├── services/
│   │   └── threatDetectionService.ts  # API service layer
│   ├── types/
│   │   └── threat.ts        # TypeScript interfaces
│   ├── utils/
│   │   └── helpers.ts       # Utility functions
│   ├── App.tsx              # Main app component
│   └── routes.ts            # Route configuration
└── styles/
    ├── theme.css            # CSS variables and theme
    └── tailwind.css         # Tailwind imports
```

## 🛠️ Installation & Setup

### Prerequisites
- Node.js 18+ 
- npm or pnpm

### Install Dependencies
```bash
npm install
# or
pnpm install
```

### Environment Variables
Create a `.env` file in the root directory:

```env
# Backend API URL (optional)
VITE_API_URL=http://localhost:8000

# Use mock data (default: true)
VITE_USE_MOCK=true
```

### Development Server
```bash
npm run dev
# or
pnpm dev
```

The application will be available at `http://localhost:5173`

### Build for Production
```bash
npm run build
# or
pnpm build
```

## 🔌 Backend Integration

The dashboard is designed to work with a FastAPI backend. Configure the following endpoints:

### API Endpoints

#### 1. Health Check
```
GET /health
Response: { "status": "healthy", "timestamp": "ISO-8601" }
```

#### 2. Single Prediction
```
POST /predict
Content-Type: application/json

Request Body:
{
  "sourceIp": "192.168.1.100",
  "destinationIp": "10.0.0.50",
  "sourcePort": 8080,
  "destinationPort": 443,
  "protocol": "TCP",
  "packetSize": 1024,
  "duration": 5.2
}

Response:
{
  "id": "pred_123",
  "timestamp": "2026-02-26T10:30:00Z",
  "sourceIp": "192.168.1.100",
  "destinationIp": "10.0.0.50",
  "sourcePort": 8080,
  "destinationPort": 443,
  "protocol": "TCP",
  "packetSize": 1024,
  "duration": 5.2,
  "prediction": "Malicious",
  "confidence": 0.92,
  "severity": "High"
}
```

#### 3. Batch Prediction
```
POST /predict/batch
Content-Type: multipart/form-data

Request Body: CSV file with columns:
- source_ip
- destination_ip
- source_port
- destination_port
- protocol
- packet_size
- duration

Response:
{
  "success": true,
  "total": 50,
  "predictions": [...]
}
```

#### 4. Get All Predictions (Optional)
```
GET /predictions
Response: Array of prediction objects
```

#### 5. Get Analytics (Optional)
```
GET /analytics
Response: {
  "normalCount": 100,
  "maliciousCount": 25,
  "timelineData": [...],
  "topMaliciousIPs": [...],
  "severityCounts": { "high": 5, "medium": 10, "low": 10 }
}
```

### Mock Mode
By default, the application runs in mock mode for development without a backend. Set `VITE_USE_MOCK=false` in `.env` to connect to a real API.

## 📊 CSV File Format

### Required Columns
```csv
source_ip,destination_ip,source_port,destination_port,protocol,packet_size,duration
192.168.1.100,10.0.0.50,8080,443,TCP,1024,5.2
172.16.0.5,8.8.8.8,53,53,UDP,512,0.1
```

### Sample Data
A sample CSV file can be downloaded from the Upload page or generated programmatically.

## ⌨️ Keyboard Shortcuts

- `Ctrl + U` (or `Cmd + U` on Mac): Navigate to Upload page
- `Ctrl + M` (or `Cmd + M` on Mac): Navigate to Manual Input page

## 🎯 Features in Detail

### Landing Page
- Hero section with animated shield icon
- Two action cards: Batch Analysis and Manual Input
- Key features overview

### Upload Page
- Drag-and-drop file upload zone
- File validation (CSV only, max 10MB)
- Preview first 5 rows before processing
- Progress indicator during upload
- Results summary with statistics
- Export functionality

### Manual Input Page
- Form with real-time validation
- IP address format checking
- Port range validation
- Protocol dropdown selection
- Instant prediction results
- Color-coded severity indicators

### Dashboard Page
- Sortable data table with all predictions
- Search by IP address
- Filter by severity level (High, Medium, Low, Normal)
- Pagination (10 items per page)
- Export filtered results to CSV
- Color-coded rows (red for malicious, default for normal)

### Analytics Page
- Summary cards: High/Medium/Low severity counts + threat rate
- Pie chart: Normal vs Malicious traffic distribution
- Line chart: Timeline of detected anomalies (24 hours)
- Bar chart: Top 5 malicious source IPs
- Real-time data updates

### Alert System
- Critical alert banner at the top
- Toast notifications for all events
- Alert history tracking
- Dismissible alerts

## 🧪 Testing

The application includes:
- Form validation testing
- IP address validation
- Port range validation
- CSV structure validation
- Mock service for development

## 🔒 Security Features

- Input sanitization to prevent XSS attacks
- IP address format validation
- File type and size validation
- HTTPS recommended for production
- Environment variable configuration for API keys

## 📱 Responsive Design

The dashboard is fully responsive and optimized for:
- **Desktop**: Full feature set with side-by-side layouts
- **Tablet**: Optimized grid layouts
- **Mobile**: Stacked layouts with touch-friendly controls

## 🎨 Customization

### Theme Colors
Edit `/src/styles/theme.css` to customize colors:
- Primary (success): `#00ff88`
- Secondary (info): `#00ccff`
- Destructive (danger): `#ff3366`

### Add New Features
1. Create new component in `/src/app/components/`
2. Add route in `/src/app/routes.ts`
3. Update navigation in `/src/app/components/Navigation.tsx`

## 📝 License

This project is open source and available under the MIT License.

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📞 Support

For issues, questions, or feature requests, please open an issue on GitHub.

## 🙏 Acknowledgments

- Built with React and modern web technologies
- UI components inspired by shadcn/ui
- Icons from Lucide React
- Charts powered by Recharts

---

**Note**: This dashboard is designed for cybersecurity research and network monitoring. Ensure compliance with applicable laws and regulations when deploying in production environments.
