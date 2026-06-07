import { Card, CardContent, CardHeader } from './ui/card';
import { Skeleton } from './ui/skeleton';

export function DashboardSkeleton() {
  return (
    <div className="space-y-6">
      {/* Header Skeleton */}
      <div className="space-y-2">
        <Skeleton className="h-10 w-64 bg-panel-raised/50" />
        <Skeleton className="h-4 w-96 bg-panel-raised/50" />
      </div>

      {/* Filters Skeleton */}
      <Card className="bg-panel-raised/50 border-line-strong">
        <CardContent className="py-6">
          <div className="grid md:grid-cols-3 gap-4">
            <Skeleton className="h-10 md:col-span-2 bg-panel-raised/50" />
            <Skeleton className="h-10 bg-panel-raised/50" />
          </div>
        </CardContent>
      </Card>

      {/* Table Skeleton */}
      <Card className="bg-panel-raised/50 border-line-strong">
        <CardHeader>
          <Skeleton className="h-6 w-48 bg-panel-raised/50" />
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {[...Array(5)].map((_, i) => (
              <div key={i} className="flex gap-4">
                <Skeleton className="h-12 flex-1 bg-panel-raised/50" />
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

export function AnalyticsSkeleton() {
  return (
    <div className="space-y-6">
      {/* Header Skeleton */}
      <div className="space-y-2">
        <Skeleton className="h-10 w-80 bg-panel-raised/50" />
        <Skeleton className="h-4 w-96 bg-panel-raised/50" />
      </div>

      {/* Summary Cards Skeleton */}
      <div className="grid md:grid-cols-4 gap-6">
        {[...Array(4)].map((_, i) => (
          <Card key={i} className="bg-panel-raised/50 border-line-strong">
            <CardContent className="p-6">
              <div className="flex items-center justify-between mb-2">
                <Skeleton className="h-8 w-8 rounded-full bg-panel-raised/50" />
                <Skeleton className="h-4 w-16 bg-panel-raised/50" />
              </div>
              <Skeleton className="h-8 w-16 mb-1 bg-panel-raised/50" />
              <Skeleton className="h-4 w-32 bg-panel-raised/50" />
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Charts Skeleton */}
      <div className="grid lg:grid-cols-2 gap-8">
        {[...Array(2)].map((_, i) => (
          <Card key={i} className="bg-panel-raised/50 border-line-strong">
            <CardHeader>
              <Skeleton className="h-6 w-48 bg-panel-raised/50" />
            </CardHeader>
            <CardContent>
              <Skeleton className="h-64 w-full bg-panel-raised/50" />
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Bar Chart Skeleton */}
      <Card className="bg-panel-raised/50 border-line-strong">
        <CardHeader>
          <Skeleton className="h-6 w-64 bg-panel-raised/50" />
        </CardHeader>
        <CardContent>
          <Skeleton className="h-64 w-full bg-panel-raised/50" />
        </CardContent>
      </Card>
    </div>
  );
}
