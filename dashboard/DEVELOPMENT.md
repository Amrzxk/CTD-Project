# Development Guide - Cyber Threat Detection Dashboard

This guide covers development workflows, best practices, and common tasks for the Cyber Threat Detection Dashboard.

## Getting Started

### Prerequisites
- Node.js 18+ (LTS recommended)
- npm 9+ or pnpm 8+
- Git
- Code editor (VS Code recommended)

### Initial Setup

1. **Clone the repository**
```bash
git clone <repository-url>
cd cyber-threat-detection-dashboard
```

2. **Install dependencies**
```bash
npm install
# or
pnpm install
```

3. **Configure environment**
```bash
cp .env.example .env
# Edit .env with your settings
```

4. **Start development server**
```bash
npm run dev
# or
pnpm dev
```

The app will be available at `http://localhost:5173`

## Development Workflow

### Daily Development

1. **Pull latest changes**
```bash
git pull origin main
```

2. **Create feature branch**
```bash
git checkout -b feature/your-feature-name
```

3. **Start dev server**
```bash
npm run dev
```

4. **Make changes and test**
- Edit files in `/src/app/`
- See live updates in browser
- Check console for errors

5. **Commit changes**
```bash
git add .
git commit -m "feat: add new feature"
```

6. **Push and create PR**
```bash
git push origin feature/your-feature-name
```

### Project Scripts

```json
{
  "dev": "vite",                    // Start dev server
  "build": "vite build",            // Build for production
  "preview": "vite preview",        // Preview production build
  "lint": "eslint src",             // Run linter
  "type-check": "tsc --noEmit"      // Check TypeScript types
}
```

## Code Organization

### Creating New Components

#### 1. Page Component
```typescript
// src/app/pages/NewPage.tsx
import { useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/card';

export default function NewPage() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-black py-12">
      <div className="container mx-auto px-4">
        <h1 className="text-4xl font-bold text-white mb-8">New Page</h1>
        {/* Content */}
      </div>
    </div>
  );
}
```

#### 2. Reusable Component
```typescript
// src/app/components/MyComponent.tsx
interface MyComponentProps {
  title: string;
  onAction: () => void;
}

export function MyComponent({ title, onAction }: MyComponentProps) {
  return (
    <div>
      <h2>{title}</h2>
      <button onClick={onAction}>Action</button>
    </div>
  );
}
```

#### 3. Add to Routes
```typescript
// src/app/routes.ts
import NewPage from './pages/NewPage';

export const router = createBrowserRouter([
  // ... existing routes
  {
    path: '/new-page',
    Component: NewPage,
  },
]);
```

### Adding New Features

#### Example: Add New Chart Type

1. **Install dependencies** (if needed)
```bash
npm install new-chart-library
```

2. **Create chart component**
```typescript
// src/app/components/NewChart.tsx
import { ResponsiveContainer, BarChart, Bar } from 'recharts';

interface NewChartProps {
  data: any[];
}

export function NewChart({ data }: NewChartProps) {
  return (
    <ResponsiveContainer width="100%" height={300}>
      <BarChart data={data}>
        <Bar dataKey="value" fill="#00ff88" />
      </BarChart>
    </ResponsiveContainer>
  );
}
```

3. **Use in page**
```typescript
import { NewChart } from '../components/NewChart';

// In your component
<NewChart data={chartData} />
```

## Working with the Service Layer

### Mock Mode (Default)

The app runs in mock mode by default for development without a backend.

**Configuration**: `.env`
```env
VITE_USE_MOCK=true
```

**Mock Data**: Automatically generated in `threatDetectionService.ts`

### Connecting to Real API

1. **Set up backend** (FastAPI)
```bash
# In backend directory
uvicorn main:app --reload
```

2. **Update environment**
```env
VITE_API_URL=http://localhost:8000
VITE_USE_MOCK=false
```

3. **Test connection**
```typescript
// Check health endpoint
const health = await threatService.checkHealth();
console.log(health.status); // 'healthy'
```

### Adding New API Endpoints

1. **Update service**
```typescript
// src/app/services/threatDetectionService.ts

async getNewData(): Promise<NewDataType> {
  if (USE_MOCK) {
    // Mock implementation
    return mockData;
  }
  
  const response = await fetch(`${API_BASE_URL}/new-endpoint`);
  return response.json();
}
```

2. **Update types**
```typescript
// src/app/types/threat.ts

export interface NewDataType {
  id: string;
  value: number;
}
```

3. **Use in component**
```typescript
const [data, setData] = useState<NewDataType | null>(null);

useEffect(() => {
  threatService.getNewData().then(setData);
}, []);
```

## Styling Guidelines

### Tailwind CSS Classes

**Layout**
```typescript
// Container with responsive padding
<div className="container mx-auto px-4">

// Responsive grid
<div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">

// Flexbox
<div className="flex items-center justify-between">
```

**Colors (Cybersecurity Theme)**
```typescript
// Primary (Green)
<Button className="bg-[#00ff88] text-gray-900">

// Secondary (Cyan)
<Badge className="bg-[#00ccff]/20 text-[#00ccff]">

// Danger (Red)
<Alert className="bg-red-500/20 border-red-500/50">

// Background gradients
<div className="bg-gradient-to-br from-gray-900 via-gray-800 to-black">
```

**Spacing**
```typescript
// Padding/Margin
<div className="p-4 mb-6 mt-8">

// Gap in flex/grid
<div className="flex gap-4">
```

**Typography**
```typescript
// Headings
<h1 className="text-4xl font-bold text-white">
<h2 className="text-2xl font-semibold text-gray-300">

// Body text
<p className="text-gray-400">
```

### Custom CSS

Only add custom CSS to `/src/styles/theme.css` for:
- CSS custom properties (variables)
- Global styles
- Complex animations

**Example**:
```css
:root {
  --custom-color: #00ff88;
}

.custom-animation {
  animation: pulse 2s infinite;
}
```

## Form Handling

### React Hook Form Pattern

```typescript
import { useForm } from 'react-hook-form';

interface FormData {
  email: string;
  password: string;
}

function MyForm() {
  const { register, handleSubmit, formState: { errors } } = useForm<FormData>();

  const onSubmit = async (data: FormData) => {
    console.log(data);
    // Process form
  };

  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      <Input
        {...register('email', {
          required: 'Email is required',
          pattern: {
            value: /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i,
            message: 'Invalid email address'
          }
        })}
      />
      {errors.email && <span>{errors.email.message}</span>}
      
      <Button type="submit">Submit</Button>
    </form>
  );
}
```

## State Management Patterns

### Local State
```typescript
const [data, setData] = useState<DataType[]>([]);
const [loading, setLoading] = useState(true);
const [error, setError] = useState<string | null>(null);
```

### Effect Hooks
```typescript
useEffect(() => {
  async function loadData() {
    setLoading(true);
    try {
      const result = await fetchData();
      setData(result);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }
  
  loadData();
}, [/* dependencies */]);
```

### Custom Hooks
```typescript
// src/app/hooks/useThreatData.ts
function useThreatData() {
  const [data, setData] = useState<ThreatPrediction[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    threatService.getAllPredictions()
      .then(setData)
      .finally(() => setLoading(false));
  }, []);

  return { data, loading };
}

// Usage
const { data, loading } = useThreatData();
```

## Animation with Motion

### Basic Animation
```typescript
import { motion } from 'motion/react';

<motion.div
  initial={{ opacity: 0, y: 20 }}
  animate={{ opacity: 1, y: 0 }}
  transition={{ duration: 0.5 }}
>
  Content
</motion.div>
```

### List Animation
```typescript
{items.map((item, idx) => (
  <motion.div
    key={item.id}
    initial={{ opacity: 0, x: -20 }}
    animate={{ opacity: 1, x: 0 }}
    transition={{ delay: idx * 0.1 }}
  >
    {item.name}
  </motion.div>
))}
```

### Exit Animation
```typescript
import { AnimatePresence } from 'motion/react';

<AnimatePresence>
  {show && (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
    >
      Content
    </motion.div>
  )}
</AnimatePresence>
```

## Testing

### Manual Testing Checklist

**Landing Page**
- [ ] Hero section loads properly
- [ ] Action cards are clickable
- [ ] Navigation works
- [ ] Animations play smoothly

**Upload Page**
- [ ] Drag-and-drop works
- [ ] File validation works (reject non-CSV, large files)
- [ ] Preview shows correct data
- [ ] Upload processes successfully
- [ ] Results display correctly
- [ ] Export downloads CSV

**Manual Input Page**
- [ ] Form validation works (IP, ports)
- [ ] Error messages display
- [ ] Submit button works
- [ ] Results show correctly
- [ ] Color coding is accurate

**Dashboard Page**
- [ ] Table loads data
- [ ] Search filters results
- [ ] Severity filter works
- [ ] Pagination works
- [ ] Export works

**Analytics Page**
- [ ] All charts render
- [ ] Data is accurate
- [ ] Responsive on mobile

### Browser Testing

Test in:
- Chrome/Edge (latest)
- Firefox (latest)
- Safari (latest)
- Mobile browsers (iOS Safari, Chrome Mobile)

### Responsive Testing

Breakpoints:
- Mobile: 320px - 767px
- Tablet: 768px - 1023px
- Desktop: 1024px+

## Debugging

### Common Issues

**1. Component not rendering**
- Check import paths
- Verify export/import syntax (default vs named)
- Check React DevTools

**2. API calls failing**
- Check `VITE_USE_MOCK` setting
- Verify `VITE_API_URL` is correct
- Check network tab in DevTools
- Review CORS configuration

**3. Styling issues**
- Check Tailwind class names
- Verify theme.css variables
- Inspect element in DevTools
- Check for specificity conflicts

**4. TypeScript errors**
- Run `npm run type-check`
- Check interface definitions
- Verify prop types
- Add type assertions if needed

### Dev Tools

**React DevTools**
- Inspect component tree
- Check props and state
- Profile performance

**Browser DevTools**
- Network tab for API calls
- Console for errors
- Elements for styling

**Vite DevTools**
- Hot module replacement (HMR)
- Build output analysis

## Performance Optimization

### Best Practices

1. **Memoize expensive computations**
```typescript
const filtered = useMemo(() => 
  data.filter(item => item.active),
  [data]
);
```

2. **Callback memoization**
```typescript
const handleClick = useCallback(() => {
  console.log('clicked');
}, []);
```

3. **Lazy load components**
```typescript
const HeavyComponent = lazy(() => import('./HeavyComponent'));

<Suspense fallback={<Loading />}>
  <HeavyComponent />
</Suspense>
```

4. **Optimize images**
- Use appropriate formats (WebP)
- Compress images
- Lazy load images below fold

5. **Code splitting**
- Split routes
- Dynamic imports for heavy libraries

## Git Workflow

### Commit Message Convention

```
type(scope): subject

body

footer
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting, no code change
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Maintenance tasks

**Examples**:
```
feat(dashboard): add export to PDF functionality
fix(upload): correct CSV parsing for special characters
docs(readme): update installation instructions
```

### Branch Naming

- `feature/description` - New features
- `fix/description` - Bug fixes
- `hotfix/description` - Critical fixes
- `refactor/description` - Code refactoring

## Troubleshooting

### Installation Issues

**Issue**: Dependencies not installing
**Solution**:
```bash
rm -rf node_modules package-lock.json
npm install
```

**Issue**: Version conflicts
**Solution**: Check Node.js version (use 18+)

### Build Issues

**Issue**: Build fails with type errors
**Solution**: Run type check first
```bash
npm run type-check
```

**Issue**: Out of memory during build
**Solution**: Increase Node memory
```bash
NODE_OPTIONS=--max-old-space-size=4096 npm run build
```

### Runtime Issues

**Issue**: White screen on load
**Solution**: Check browser console for errors

**Issue**: Environment variables not working
**Solution**: Ensure prefix is `VITE_` and restart dev server

**Issue**: Hot reload not working
**Solution**: Restart dev server

## Resources

### Documentation
- [React Docs](https://react.dev)
- [React Router](https://reactrouter.com)
- [Tailwind CSS](https://tailwindcss.com)
- [Recharts](https://recharts.org)
- [Motion](https://motion.dev)

### Tools
- [VS Code](https://code.visualstudio.com)
- [React DevTools](https://react.dev/learn/react-developer-tools)
- [Tailwind CSS IntelliSense](https://marketplace.visualstudio.com/items?itemName=bradlc.vscode-tailwindcss)

### Community
- GitHub Issues
- Stack Overflow
- React Discord

---

**Happy Coding!** 🚀
