import { Link } from 'react-router';
import { Shield, Home } from 'lucide-react';
import { Button } from '../components/ui/button';
import { motion } from 'motion/react';

export default function NotFoundPage() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-bg via-bg to-bg flex items-center justify-center">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="text-center"
      >
        <div className="flex justify-center mb-6">
          <div className="p-4 rounded-full bg-panel/80 backdrop-blur">
            <Shield className="w-16 h-16 text-faint" />
          </div>
        </div>
        
        <h1 className="text-6xl font-bold text-foreground mb-4">404</h1>
        <p className="text-xl text-muted-foreground mb-8">Page not found</p>
        <p className="text-sm text-muted-foreground mb-8">
          The page you're looking for doesn't exist or has been moved.
        </p>
        
        <Link to="/">
          <Button className="bg-brand hover:bg-brand/80 text-[var(--on-brand)] font-semibold">
            <Home className="mr-2 h-4 w-4" />
            Return to Home
          </Button>
        </Link>
      </motion.div>
    </div>
  );
}