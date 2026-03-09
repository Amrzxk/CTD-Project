# Cyber Threat Detection Dashboard - Architecture Documentation

## Overview

This document describes the architecture and technical implementation of the Cyber Threat Detection Dashboard, a React-based web application for AI-powered network anomaly detection.

## Technology Stack

### Frontend Framework
- **React 18.3.1**: Modern React with functional components and hooks
- **TypeScript**: Type-safe development with interfaces and strict typing
- **Vite**: Fast development server and optimized production builds

### Routing & State Management
- **React Router 7.13.0**: Client-side routing with data mode pattern
- **React Hook Form 7.55.0**: Efficient form state management with validation
- **Local State**: Component-level state with useState and useEffect hooks

### UI & Styling
- **Tailwind CSS 4.1.12**: Utility-first CSS framework
- **Radix UI**: Accessible, unstyled component primitives
- **Motion (Framer Motion) 12.23.24**: Animation library for smooth transitions
- **Lucide React**: Icon library

### Data Visualization
- **Recharts 2.15.2**: Composable charting library built on React components
  - Pie charts for distribution
  - Line charts for timelines
  - Bar charts for comparisons

### UI Components
- **Sonner 2.0.3**: Toast notifications
- **Custom UI Library**: Built on Radix UI primitives with Tailwind styling

## Project Structure

```
src/
├── app/
│   ├── components/
│   │   ├── ui/                      # Reusable UI components (buttons, cards, etc.)
│   │   ├── Navigation.tsx           # Top navigation bar with routing
│   │   ├── AlertBanner.tsx          # Critical threat alert banner
│   │   ├── APIDocumentation.tsx     # API endpoint documentation
│   │   ├── LoadingSkeletons.tsx     # Loading state components
│   │   └── QuickStartGuide.tsx      # First-time user guide
│   │
│   ├── pages/
│   │   ├── LandingPage.tsx          # Home page with feature overview
│   │   ├── UploadPage.tsx           # CSV file upload and batch processing
│   │   ├── ManualInputPage.tsx      # Manual threat analysis form
│   │   ├── DashboardPage.tsx        # Results table with filters
│   │   └── AnalyticsPage.tsx        # Charts and statistics
│   │
│   ├── services/
│   │   └── threatDetectionService.ts # API service layer with mock data
│   │
│   ├── types/
│   │   └── threat.ts                # TypeScript type definitions
│   │
│   ├── utils/
│   │   └── helpers.ts               # Utility functions (validation, formatting)
│   │
│   ├── App.tsx                      # Main application component
│   └── routes.ts                    # Route configuration
│
└── styles/
    ├── theme.css                    # CSS custom properties and design tokens
    ├── tailwind.css                 # Tailwind imports
    └── fonts.css                    # Font imports
```

## Core Components

### 1. Landing Page
**Purpose**: Entry point with feature overview and navigation

**Features**:
- Animated hero section with gradient text
- Two main action cards (Batch Analysis, Manual Input)
- Feature grid with hover effects
- API documentation display
- Keyboard shortcuts reference

**Animations**:
- Fade-in on load
- Pulsing shield icon with box-shadow
- Card hover scale effects

### 2. Upload Page
**Purpose**: CSV file upload and batch threat analysis

**Features**:
- Drag-and-drop file zone
- File validation (type, size)
- CSV preview (first 5 rows)
- Progress indicator
- Results summary
- Export functionality

**Validation**:
- File type: `.csv` only
- Max size: 10MB
- Required columns: source_ip, destination_ip, source_port, destination_port, protocol, packet_size, duration

**State Management**:
```typescript
const [file, setFile] = useState<File | null>(null);
const [uploading, setUploading] = useState(false);
const [progress, setProgress] = useState(0);
const [preview, setPreview] = useState<string[][] | null>(null);
const [results, setResults] = useState<ThreatPrediction[] | null>(null);
```

### 3. Manual Input Page
**Purpose**: Real-time single connection threat analysis

**Features**:
- Dynamic form with React Hook Form
- Real-time validation
- IP address format checking
- Port range validation (0-65535)
- Protocol selection dropdown
- Instant prediction results
- Color-coded severity display

**Form Validation**:
```typescript
{
  sourceIp: {
    required: 'Source IP is required',
    validate: (value) => isValidIPv4(value) || 'Invalid IPv4 address format'
  },
  sourcePort: {
    required: 'Source port is required',
    valueAsNumber: true,
    validate: (value) => isValidPort(value) || 'Port must be between 0-65535'
  }
}
```

### 4. Dashboard Page
**Purpose**: View, filter, and export all predictions

**Features**:
- Data table with all predictions
- Search by IP address
- Filter by severity (High, Medium, Low, Normal)
- Pagination (10 items per page)
- Color-coded rows
- Export to CSV

**Filtering Logic**:
```typescript
// Search filter
filtered = filtered.filter(p => 
  p.sourceIp.includes(searchTerm) || 
  p.destinationIp.includes(searchTerm)
);

// Severity filter
if (severityFilter !== 'all') {
  filtered = filtered.filter(p => 
    p.prediction === 'Malicious' && 
    p.severity?.toLowerCase() === severityFilter
  );
}
```

### 5. Analytics Page
**Purpose**: Visualize threat intelligence and statistics

**Features**:
- Summary cards (High/Medium/Low severity counts, threat rate)
- Pie chart: Normal vs Malicious distribution
- Line chart: 24-hour timeline
- Bar chart: Top 5 malicious IPs

**Charts Configuration**:
```typescript
// Recharts components
<ResponsiveContainer width="100%" height={300}>
  <PieChart>
    <Pie 
      data={pieData}
      dataKey="value"
      label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(1)}%`}
    />
    <Tooltip />
  </PieChart>
</ResponsiveContainer>
```

## Service Layer

### Threat Detection Service
**Location**: `/src/app/services/threatDetectionService.ts`

**Purpose**: Abstraction layer for API communication with mock fallback

**Key Methods**:

```typescript
class ThreatDetectionService {
  // Single prediction
  async predictSingle(input: ManualInputForm): Promise<ThreatPrediction>
  
  // Batch prediction (CSV upload)
  async predictBatch(file: File): Promise<BatchPredictionResult>
  
  // Get all predictions
  async getAllPredictions(): Promise<ThreatPrediction[]>
  
  // Get analytics data
  async getAnalytics(): Promise<AnalyticsData>
  
  // Health check
  async checkHealth(): Promise<BackendHealth>
  
  // Alert management
  getAlerts(): AlertNotification[]
  clearAlert(id: string): void
  
  // Export to CSV
  exportToCSV(predictions: ThreatPrediction[]): string
}
```

**Mock Mode**:
- Generates realistic fake data
- Simulates network delays
- Creates random predictions with confidence scores
- Automatically triggers alerts for high-severity threats

**Configuration**:
```typescript
const USE_MOCK = import.meta.env.VITE_USE_MOCK !== 'false';
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
```

## Type System

### Core Types

```typescript
// Threat prediction result
interface ThreatPrediction {
  id: string;
  timestamp: string;
  sourceIp: string;
  destinationIp: string;
  sourcePort: number;
  destinationPort: number;
  protocol: string;
  packetSize: number;
  duration: number;
  prediction: 'Normal' | 'Malicious';
  confidence: number;
  severity?: 'High' | 'Medium' | 'Low';
}

// Manual input form data
interface ManualInputForm {
  sourceIp: string;
  destinationIp: string;
  sourcePort: number;
  destinationPort: number;
  protocol: string;
  packetSize: number;
  duration: number;
}

// Analytics data structure
interface AnalyticsData {
  normalCount: number;
  maliciousCount: number;
  timelineData: { time: string; count: number }[];
  topMaliciousIPs: { ip: string; count: number }[];
  severityCounts: {
    high: number;
    medium: number;
    low: number;
  };
}
```

## Utility Functions

### Validation
```typescript
// IPv4 address validation
isValidIPv4(ip: string): boolean

// Port number validation (0-65535)
isValidPort(port: number): boolean

// CSV structure validation
validateCSVStructure(rows: string[][]): { valid: boolean; error?: string }
```

### Formatting
```typescript
// Format ISO timestamp to readable string
formatDateTime(dateString: string): string

// Format confidence as percentage
formatConfidence(confidence: number): string

// Get color classes based on severity/prediction
getSeverityColor(severity: 'High' | 'Medium' | 'Low'): string
getPredictionColor(prediction: 'Normal' | 'Malicious'): string
```

### Data Processing
```typescript
// Parse CSV content
parseCSV(content: string): string[][]

// Download file to user's device
downloadFile(content: string, filename: string, mimeType: string): void

// Sanitize input to prevent XSS
sanitizeInput(input: string): string

// Debounce function for search
debounce<T>(func: T, wait: number): Function
```

## Design System

### Color Palette
```css
/* Cybersecurity Theme */
--primary: #00ff88      /* Neon Green - Success, Safe */
--secondary: #00ccff    /* Cyan Blue - Information */
--destructive: #ff3366  /* Red - Danger, Malicious */
--background: #0a0a0f   /* Dark background */
--card: #1a1a24         /* Card background */
--muted: #2a2a3a        /* Muted elements */
```

### Typography
- Font size: 16px base
- Font weights: 400 (normal), 500 (medium)
- Headings: h1-h4 with consistent sizing

### Spacing & Layout
- Border radius: 0.625rem (10px)
- Container: max-width with responsive padding
- Grid layouts: CSS Grid and Tailwind utilities

### Animations
- Duration: 200ms-600ms for UI interactions
- Easing: Default cubic-bezier
- Motion library for complex animations

## State Management Strategy

### Component-Level State
- Use `useState` for local UI state
- Use `useEffect` for side effects and data fetching
- Pass props for parent-child communication

### Form State
- React Hook Form for all forms
- Validation schemas defined inline
- Real-time validation feedback

### Global State
- No Redux/Zustand needed for this app
- Service layer singleton for data persistence
- LocalStorage for user preferences

## Performance Optimizations

### Code Splitting
- React Router with lazy loading (ready for implementation)
- Dynamic imports for heavy components

### Memoization
- Use `useMemo` for expensive computations
- Use `useCallback` for event handlers passed to children

### Rendering Optimization
- Conditional rendering for large lists
- Pagination to limit DOM nodes
- Skeleton loaders for perceived performance

### Bundle Size
- Tree-shaking with Vite
- Minimal dependencies
- On-demand component imports

## Security Considerations

### Input Validation
- Client-side validation for all user inputs
- IP address format checking with regex
- Port range validation
- File type and size restrictions

### XSS Prevention
- Input sanitization function
- React's built-in XSS protection
- Avoid dangerouslySetInnerHTML

### CSRF Protection
- Same-origin policy
- HTTP-only cookies (backend responsibility)
- CORS configuration (backend responsibility)

### Data Privacy
- No PII collection in mock mode
- Clear warnings about data sensitivity
- Environment variable for API URLs

## Testing Strategy

### Unit Tests (Recommended)
```typescript
// Utility function tests
describe('isValidIPv4', () => {
  it('should validate correct IPv4 addresses', () => {
    expect(isValidIPv4('192.168.1.1')).toBe(true);
  });
  
  it('should reject invalid IPv4 addresses', () => {
    expect(isValidIPv4('256.1.1.1')).toBe(false);
  });
});
```

### Integration Tests (Recommended)
- Form submission flows
- API service mocking
- Navigation between pages

### E2E Tests (Recommended)
- Complete user workflows
- File upload process
- Data table interactions

## Deployment

### Build Process
```bash
npm run build
```

Output: `/dist` directory with optimized static files

### Environment Variables
```env
VITE_API_URL=https://api.example.com
VITE_USE_MOCK=false
```

### Hosting Options
- **Vercel**: Zero-config deployment
- **Netlify**: Continuous deployment from Git
- **AWS S3 + CloudFront**: Static hosting with CDN
- **Docker**: Containerized deployment

### Production Checklist
- [ ] Set `VITE_USE_MOCK=false`
- [ ] Configure real API URL
- [ ] Enable HTTPS
- [ ] Set up error tracking (Sentry, etc.)
- [ ] Configure analytics (optional)
- [ ] Test on multiple devices/browsers
- [ ] Optimize images and assets
- [ ] Enable gzip/brotli compression

## Future Enhancements

### Planned Features
1. **Real-time Updates**: WebSocket integration for live data
2. **User Authentication**: Login/logout with JWT
3. **Multi-language Support**: i18n with Arabic and English
4. **Advanced Filtering**: Date range, protocol type, port ranges
5. **Report Generation**: PDF export with charts
6. **Alert Rules**: Custom alert configuration
7. **Historical Data**: Time-series analysis
8. **Machine Learning Integration**: Train custom models

### Technical Improvements
1. **Service Workers**: Offline support
2. **PWA Features**: Install prompt, notifications
3. **Lazy Loading**: Route-based code splitting
4. **State Management**: Zustand or Redux for complex state
5. **API Caching**: React Query for data fetching
6. **Error Boundaries**: Better error handling
7. **Accessibility**: ARIA labels, keyboard navigation
8. **Performance Monitoring**: Web Vitals tracking

## Contributing

### Code Style
- Follow ESLint configuration
- Use Prettier for formatting
- TypeScript strict mode enabled
- Meaningful variable names

### Git Workflow
1. Create feature branch
2. Make changes with descriptive commits
3. Run tests and linting
4. Submit pull request
5. Code review and merge

### Documentation
- Update README for user-facing changes
- Update ARCHITECTURE.md for technical changes
- Add JSDoc comments for complex functions
- Keep type definitions up to date

## Support & Maintenance

### Issue Tracking
- GitHub Issues for bugs and features
- Label categorization (bug, enhancement, question)
- Issue templates for consistency

### Versioning
- Semantic versioning (MAJOR.MINOR.PATCH)
- Changelog for release notes
- Migration guides for breaking changes

---

**Last Updated**: February 26, 2026  
**Version**: 1.0.0  
**Maintainer**: Development Team
