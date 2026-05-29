import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { toast } from 'sonner';

import { liveTrafficStream } from '../services/threatDetectionService';
import { RingBufferStore } from '../hooks/useRingBuffer';
import { useAuth } from './AuthContext';
import type {
  DetectionMode,
  LivePacket,
  LiveSession,
  LiveSource,
  ReplaySpeed,
  LiveStreamLifecycleEvent,
  SessionLogFormat,
} from '../types/threat';

const RING_CAPACITY = 2000;
const EPS_WINDOW_MS = 5000;

export interface LiveStreamContextValue {
  /** Backing store for the bounded event ring. Consumers call
   *  `useRingBufferItems(store)` / `useRingBufferCount(store)` to read with
   *  fine-grained re-render control. Holding the store handle does not
   *  trigger a re-render — only reading items/count does. */
  store: RingBufferStore<LivePacket>;
  /** Rolling 5-second EPS. Sampled at 1 Hz and only updated when the value
   *  meaningfully changes, so this re-renders consumers ~once per second. */
  eps: number;
  /** Current server-side session (mirrored from /live/session + lifecycle). */
  activeSession: LiveSession | null;
  connected: boolean;
  reconnecting: { attempt: number; in_ms: number } | null;
  /** Detail-drawer selection — surviving cross-route navigation. */
  selected: LivePacket | null;
  setSelected: (p: LivePacket | null) => void;
  startSession: (
    source: LiveSource,
    detection_mode: DetectionMode,
    speed: number | null,
    persist_to_alerts?: boolean | null,
  ) => Promise<LiveSession>;
  stopSession: () => Promise<void>;
  attachPcap: (sessionId: string, file: File) => Promise<LiveSession>;
  sessionLogUrl: (sessionId: string, format: SessionLogFormat) => string;
  downloadSessionLog: (sessionId: string, format: SessionLogFormat) => Promise<void>;
  /** Drop the visible ring + reset EPS tracking. Does NOT touch the
   *  server session or the on-disk session log. */
  clear: () => void;
  /** Force a re-fetch of /live/session — used after route mount to sync
   *  the activeSession from another worker. */
  refreshActiveSession: () => Promise<void>;
}

const LiveStreamContext = createContext<LiveStreamContextValue | null>(null);

/** App-shell provider — mount once under RootLayout so the live ring buffer
 *  and SSE subscription survive route navigation.
 *
 *  The store and EPS-stamp array live in refs (no per-event re-renders).
 *  Lifecycle state (activeSession / connected / reconnecting) sits in
 *  setState because changes are infrequent. The 1 Hz EPS tick uses a
 *  setState only when the rounded value moves. */
export function LiveStreamProvider({ children }: { children: ReactNode }) {
  const { user } = useAuth();

  // Stable store handle — never recreated, survives consumer remounts.
  const storeRef = useRef<RingBufferStore<LivePacket> | null>(null);
  if (storeRef.current === null) {
    storeRef.current = new RingBufferStore<LivePacket>(RING_CAPACITY);
  }
  const store = storeRef.current;

  const epsStampsRef = useRef<number[]>([]);
  const [eps, setEps] = useState(0);

  const [activeSession, setActiveSession] = useState<LiveSession | null>(null);
  const [connected, setConnected] = useState(false);
  const [reconnecting, setReconnecting] =
    useState<{ attempt: number; in_ms: number } | null>(null);
  const [selected, setSelected] = useState<LivePacket | null>(null);

  // -------------------------------------------------------------------
  // SSE subscriptions — registered once, live for the provider's
  // lifetime (i.e., as long as the user is authenticated).
  // -------------------------------------------------------------------

  useEffect(() => {
    const unsub = liveTrafficStream.subscribe((packet: LivePacket) => {
      store.push(packet);
      const stamps = epsStampsRef.current;
      stamps.push(Date.now());
      const cutoff = Date.now() - EPS_WINDOW_MS;
      while (stamps.length && stamps[0] < cutoff) stamps.shift();
    });
    return () => {
      unsub();
    };
  }, [store]);

  useEffect(() => {
    const unsub = liveTrafficStream.onLifecycle(
      (ev: LiveStreamLifecycleEvent) => {
        switch (ev.kind) {
          case 'open':
            setConnected(true);
            setReconnecting(null);
            break;
          case 'reconnecting':
            setConnected(false);
            setReconnecting({ attempt: ev.attempt, in_ms: ev.in_ms });
            break;
          case 'closed':
            setConnected(false);
            setReconnecting(null);
            break;
          case 'session_ended':
            setConnected(false);
            setReconnecting(null);
            setActiveSession(null);
            // Provider-level toast: fires even if /live isn't mounted, so
            // an analyst triaging on /alerts learns their session ended.
            toast.info(
              `Live session ended${ev.reason ? ` — ${ev.reason}` : ''}.`,
            );
            break;
        }
      },
    );
    return () => {
      unsub();
    };
  }, []);

  // 1 Hz EPS tick — cheap, only setState when the displayed value moves.
  useEffect(() => {
    const handle = window.setInterval(() => {
      const cutoff = Date.now() - EPS_WINDOW_MS;
      const stamps = epsStampsRef.current;
      while (stamps.length && stamps[0] < cutoff) stamps.shift();
      const next = (stamps.length * 1000) / EPS_WINDOW_MS;
      setEps((prev) => (Math.abs(prev - next) < 0.05 ? prev : next));
    }, 1000);
    return () => window.clearInterval(handle);
  }, []);

  // -------------------------------------------------------------------
  // Active-session sync on first auth — pick up a session that may have
  // been started in another tab or before this page was open.
  // -------------------------------------------------------------------

  const refreshActiveSession = useCallback(async () => {
    try {
      const session = await liveTrafficStream.fetchActiveSession();
      if (!session) {
        // Server says no session; if our local state thinks there is one,
        // clear it. Don't touch the ring — the user may want to review
        // events from the just-stopped session.
        setActiveSession(null);
        return;
      }
      setActiveSession(session);
      // resumeSession sets the session id on the singleton so the SSE URL
      // carries `?session=<id>` and the API can shadow-resolve cross-worker.
      // No-op if we're already connected to the same id.
      if (liveTrafficStream.sessionId !== session.session_id) {
        liveTrafficStream.resumeSession(session.session_id);
      }
    } catch {
      /* silent — most often a transient 401/5xx during deploys */
    }
  }, []);

  useEffect(() => {
    if (!user) return;
    void refreshActiveSession();
  }, [user, refreshActiveSession]);

  // -------------------------------------------------------------------
  // Logout handling — tear the SSE down so a stale connection doesn't
  // hold a worker socket open after the cookie is gone.
  // -------------------------------------------------------------------

  useEffect(() => {
    if (user) return;
    liveTrafficStream.disconnect();
    setActiveSession(null);
    setConnected(false);
    setReconnecting(null);
    setSelected(null);
    store.clear();
    epsStampsRef.current = [];
    setEps(0);
  }, [user, store]);

  // -------------------------------------------------------------------
  // Actions
  // -------------------------------------------------------------------

  const clear = useCallback(() => {
    store.clear();
    epsStampsRef.current = [];
    setEps(0);
    setSelected(null);
  }, [store]);

  const startSession = useCallback(
    async (
      source: LiveSource,
      detection_mode: DetectionMode,
      speed: number | null,
      persist_to_alerts: boolean | null = null,
    ): Promise<LiveSession> => {
      // Drop any visible state from the prior session first — see
      // SESSION_HANDOFF #3, the visible "events from session A leaking
      // into session B" case.
      clear();
      const session = await liveTrafficStream.startSession(
        source,
        detection_mode,
        speed,
        persist_to_alerts,
      );
      setActiveSession(session);
      return session;
    },
    [clear],
  );

  const stopSession = useCallback(async () => {
    await liveTrafficStream.stopSession();
    setActiveSession(null);
  }, []);

  const attachPcap = useCallback(
    async (sessionId: string, file: File): Promise<LiveSession> => {
      const updated = await liveTrafficStream.attachPcap(sessionId, file);
      setActiveSession(updated);
      return updated;
    },
    [],
  );

  const sessionLogUrl = useCallback(
    (sessionId: string, format: SessionLogFormat) =>
      liveTrafficStream.sessionLogUrl(sessionId, format),
    [],
  );

  const downloadSessionLog = useCallback(
    (sessionId: string, format: SessionLogFormat) =>
      liveTrafficStream.downloadSessionLog(sessionId, format),
    [],
  );

  const value = useMemo<LiveStreamContextValue>(
    () => ({
      store,
      eps,
      activeSession,
      connected,
      reconnecting,
      selected,
      setSelected,
      startSession,
      stopSession,
      attachPcap,
      sessionLogUrl,
      downloadSessionLog,
      clear,
      refreshActiveSession,
    }),
    [
      store,
      eps,
      activeSession,
      connected,
      reconnecting,
      selected,
      startSession,
      stopSession,
      attachPcap,
      sessionLogUrl,
      downloadSessionLog,
      clear,
      refreshActiveSession,
    ],
  );

  return (
    <LiveStreamContext.Provider value={value}>
      {children}
    </LiveStreamContext.Provider>
  );
}

export function useLiveStream(): LiveStreamContextValue {
  const ctx = useContext(LiveStreamContext);
  if (ctx === null) {
    throw new Error('useLiveStream must be used inside <LiveStreamProvider>');
  }
  return ctx;
}
