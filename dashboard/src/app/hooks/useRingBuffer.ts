import { useCallback, useMemo, useRef, useSyncExternalStore } from 'react';

/**
 * Bounded ring buffer suitable for hours-long live streams.
 *
 * Two-layer design:
 *
 *  1. **`RingBufferStore`** — a plain (non-React) store that owns the backing
 *     array and the subscriber set. Lives outside React so it can survive
 *     consumer unmounts (e.g., navigating away from `/live` while the SSE
 *     subscription keeps pushing events into it).
 *  2. **Hooks** — `useRingBufferItems(store)` and `useRingBufferCount(store)`
 *     wrap `useSyncExternalStore` so only the components that read items /
 *     count actually re-render. A consumer that only needs the store handle
 *     (e.g., to call `clear()`) does not re-render on push.
 *
 * Why a custom store instead of `setState(prev => [next, ...prev.slice(0, N-1)])`?
 *
 *  1. **No allocation per push.** A fresh array allocation on every event would
 *     destroy long-run GC behaviour at 100+ events/sec. Backing storage is a
 *     fixed-length array used as a circular buffer.
 *  2. **Stable identity** for the items snapshot. Each push freshly slices the
 *     backing array so React diffing works.
 *  3. **Total-pushed counter.** `count` is monotonic across the buffer's
 *     lifetime; consumers use it for EPS calculations and to detect drops.
 *
 * The buffer surface intentionally exposes ``items: T[]`` newest-first. That
 * matches existing UI patterns elsewhere in the dashboard (live tables prepend).
 */
export class RingBufferStore<T> {
  private slots: T[] = [];
  private readonly cap: number;
  private _count = 0;
  private itemsSnapshot: T[] = [];
  private listeners: Set<() => void> = new Set();

  constructor(capacity: number) {
    this.cap = Math.max(1, capacity | 0);
  }

  /** Append a new item. Drops the oldest when capacity is exceeded. */
  push(item: T): void {
    this.slots.unshift(item);
    if (this.slots.length > this.cap) this.slots.length = this.cap;
    // Fresh slice — useSyncExternalStore demands a stable reference between
    // calls when nothing changed, and a new one when it did. Slice() handles
    // both at the cost of an O(n) copy per push (n <= cap; fine at cap=2000).
    this.itemsSnapshot = this.slots.slice();
    this._count += 1;
    this.notify();
  }

  /** Drop everything. Resets the monotonic counter. */
  clear(): void {
    this.slots = [];
    this.itemsSnapshot = [];
    this._count = 0;
    this.notify();
  }

  /** useSyncExternalStore contract — register a change listener. */
  subscribe = (cb: () => void): (() => void) => {
    this.listeners.add(cb);
    return () => {
      this.listeners.delete(cb);
    };
  };

  /** Stable snapshot of the items array, newest-first. */
  getItems = (): T[] => this.itemsSnapshot;

  /** Monotonic push count since construction or last `clear()`. */
  getCount = (): number => this._count;

  private notify(): void {
    this.listeners.forEach((fn) => {
      try {
        fn();
      } catch {
        /* a misbehaving consumer must not break the others */
      }
    });
  }
}

/** Subscribe to a store's items array. Re-renders on every push/clear. */
export function useRingBufferItems<T>(store: RingBufferStore<T>): T[] {
  return useSyncExternalStore(store.subscribe, store.getItems, store.getItems);
}

/** Subscribe to a store's monotonic push count. Re-renders on every push/clear. */
export function useRingBufferCount<T>(store: RingBufferStore<T>): number {
  return useSyncExternalStore(store.subscribe, store.getCount, store.getCount);
}

/**
 * Legacy React-owned hook — kept for callers that want a self-contained
 * ring buffer inside one component (the buffer dies on unmount). For
 * cross-route survival, instantiate `RingBufferStore` outside React and
 * read it with the hooks above.
 */
export interface RingBuffer<T> {
  items: T[];
  push: (item: T) => void;
  clear: () => void;
  count: number;
}

export function useRingBuffer<T>(capacity: number): RingBuffer<T> {
  const storeRef = useRef<RingBufferStore<T> | null>(null);
  if (storeRef.current === null) {
    storeRef.current = new RingBufferStore<T>(capacity);
  }
  const store = storeRef.current;
  const items = useRingBufferItems(store);
  const count = useRingBufferCount(store);
  const push = useCallback((item: T) => store.push(item), [store]);
  const clear = useCallback(() => store.clear(), [store]);
  return useMemo(
    () => ({ items, push, clear, count }),
    [items, push, clear, count],
  );
}
