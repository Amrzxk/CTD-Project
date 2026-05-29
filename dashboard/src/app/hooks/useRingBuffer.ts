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
  // Events staged by push() but not yet folded into `slots`/the snapshot.
  // Flushed once per animation frame so a high-rate stream (e.g. a max-speed
  // PCAP replay emitting thousands of events/sec) coalesces into a single
  // snapshot rebuild + single re-render per frame instead of one per event.
  private pending: T[] = [];
  private flushHandle: number | null = null;
  private flushIsRaf = false;

  constructor(capacity: number) {
    this.cap = Math.max(1, capacity | 0);
  }

  /** Stage a new item. O(1) — the actual snapshot rebuild + notify happen on
   *  the next scheduled flush. Drops the oldest when capacity is exceeded
   *  (enforced at flush time). */
  push(item: T): void {
    this.pending.push(item);
    this.scheduleFlush();
  }

  /** Drop everything. Resets the monotonic counter and cancels any pending
   *  flush so staged-but-unrendered events don't resurface after a clear. */
  clear(): void {
    this.cancelFlush();
    this.slots = [];
    this.itemsSnapshot = [];
    this.pending = [];
    this._count = 0;
    this.notify();
  }

  /** Schedule a single coalesced flush. No-op if one is already pending. */
  private scheduleFlush(): void {
    if (this.flushHandle !== null) return;
    if (typeof requestAnimationFrame === 'function') {
      this.flushIsRaf = true;
      this.flushHandle = requestAnimationFrame(() => this.flush());
    } else {
      // Test / SSR fallback — no rAF available.
      this.flushIsRaf = false;
      this.flushHandle = setTimeout(() => this.flush(), 16) as unknown as number;
    }
  }

  private cancelFlush(): void {
    if (this.flushHandle === null) return;
    if (this.flushIsRaf && typeof cancelAnimationFrame === 'function') {
      cancelAnimationFrame(this.flushHandle);
    } else {
      clearTimeout(this.flushHandle);
    }
    this.flushHandle = null;
  }

  /** Fold all staged events into the buffer in one pass, rebuild the snapshot
   *  once, advance the monotonic counter by the batch size, and notify once. */
  private flush(): void {
    this.flushHandle = null;
    const batch = this.pending;
    if (batch.length === 0) return;
    this.pending = [];
    // `slots` is newest-first. The batch arrived oldest→newest; unshifting in
    // that order naturally leaves the newest event at index 0.
    for (let i = 0; i < batch.length; i++) {
      this.slots.unshift(batch[i]);
    }
    if (this.slots.length > this.cap) this.slots.length = this.cap;
    // Single fresh slice for the whole batch — useSyncExternalStore needs a
    // stable reference between flushes and a new one when items changed.
    this.itemsSnapshot = this.slots.slice();
    this._count += batch.length;
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
