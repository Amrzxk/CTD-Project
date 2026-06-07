import { Shield, Upload, PenLine, Radio, Target, ArrowRight, Layers, ScanLine } from 'lucide-react';
import { Link } from 'react-router';
import { motion } from 'motion/react';
import { APIDocumentation } from '../components/APIDocumentation';

const METRICS = [
  { value: '99.58%', label: 'E2E Accuracy', accent: true },
  { value: '0.9964', label: 'Weighted F1' },
  { value: '15', label: 'Attack Classes' },
  { value: '~111k/s', label: 'Flows Inferred' },
];

const CAPABILITIES = [
  { to: '/live', icon: Radio, title: 'Live Stream', desc: 'Real-time per-flow verdicts over SSE, ML + Snort correlated.' },
  { to: '/upload', icon: Upload, title: 'Batch Analysis', desc: 'Drop a PCAP or CSV — features extracted and scored in seconds.' },
  { to: '/manual', icon: PenLine, title: 'Manual Flow', desc: 'Hand-craft a flow and watch it route through all three stages.' },
  { to: '/mitre', icon: Target, title: 'MITRE ATT&CK', desc: 'Every detection enriched and mapped to tactics & techniques.' },
];

const fade = (delay = 0) => ({
  initial: { opacity: 0, y: 14 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.5, delay, ease: 'easeOut' as const },
});

export default function LandingPage() {
  return (
    <div className="min-h-screen">
      {/* Marketing header */}
      <header className="sticky top-0 z-20 border-b border-line bg-bg/80 backdrop-blur-md">
        <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-6">
          <Link to="/" className="flex items-center gap-2.5">
            <span className="grid size-9 place-items-center rounded-md border border-brand/30 bg-brand/10">
              <Shield className="size-5 text-brand" />
            </span>
            <span className="font-mono text-sm font-semibold tracking-tight text-foreground">H-IDS</span>
          </Link>
          <Link
            to="/login"
            className="inline-flex items-center gap-1.5 rounded-md bg-brand px-4 py-2 text-sm font-semibold text-[var(--on-brand)] transition-colors hover:bg-brand-bright"
          >
            Open Console <ArrowRight className="size-4" />
          </Link>
        </div>
      </header>

      <div className="mx-auto max-w-6xl px-6">
        {/* Hero */}
        <section className="py-20 text-center md:py-28">
          <motion.div {...fade(0)} className="mb-5 flex justify-center">
            <span className="scanline inline-flex items-center gap-2 rounded-full border border-line bg-panel px-3 py-1">
              <ScanLine className="size-3.5 text-brand" />
              <span className="eyebrow">Hybrid IDS · ML + Signatures</span>
            </span>
          </motion.div>

          <motion.h1
            {...fade(0.06)}
            className="mx-auto max-w-3xl text-balance text-4xl font-semibold leading-[1.1] tracking-tight text-foreground md:text-6xl"
          >
            Hybrid intrusion detection, built for the SOC.
          </motion.h1>

          <motion.p
            {...fade(0.12)}
            className="mx-auto mt-6 max-w-2xl text-balance text-lg text-muted-foreground"
          >
            A three-tier ML classifier and Snort 3 signatures, correlated into one verdict —
            streamed live, triaged in a single queue.
          </motion.p>

          <motion.div {...fade(0.18)} className="mt-9 flex flex-wrap justify-center gap-3">
            <Link
              to="/live"
              className="inline-flex items-center gap-2 rounded-md bg-brand px-5 py-2.5 text-sm font-semibold text-[var(--on-brand)] transition-colors hover:bg-brand-bright"
            >
              <Radio className="size-4" /> Open Live Stream
            </Link>
            <Link
              to="/upload"
              className="inline-flex items-center gap-2 rounded-md border border-line bg-panel px-5 py-2.5 text-sm font-medium text-foreground transition-colors hover:border-line-strong hover:bg-panel-raised"
            >
              <Upload className="size-4" /> Analyze a Capture
            </Link>
          </motion.div>
        </section>

        {/* Metrics strip */}
        <motion.section
          {...fade(0.24)}
          className="grid grid-cols-2 gap-px overflow-hidden rounded-xl border border-line bg-line md:grid-cols-4"
        >
          {METRICS.map((m) => (
            <div key={m.label} className="bg-panel px-6 py-7 text-center">
              <div
                className={`font-mono text-3xl font-semibold tabular-nums ${m.accent ? 'text-brand-text' : 'text-foreground'}`}
              >
                {m.value}
              </div>
              <div className="eyebrow mt-2 justify-center">{m.label}</div>
            </div>
          ))}
        </motion.section>

        {/* Capabilities */}
        <section className="py-20">
          <div className="mb-8 flex items-center gap-2">
            <Layers className="size-4 text-brand" />
            <h2 className="text-xl font-semibold text-foreground">What you can do</h2>
          </div>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {CAPABILITIES.map((c, i) => (
              <motion.div key={c.to} {...fade(0.28 + i * 0.05)}>
                <Link
                  to={c.to}
                  className="group flex h-full flex-col rounded-xl border border-line bg-panel p-5 transition-colors hover:border-brand/40"
                >
                  <span className="grid size-10 place-items-center rounded-lg border border-line bg-panel-raised transition-colors group-hover:border-brand/40 group-hover:bg-brand/10">
                    <c.icon className="size-5 text-muted-foreground transition-colors group-hover:text-brand" />
                  </span>
                  <h3 className="mt-4 text-base font-semibold text-foreground">{c.title}</h3>
                  <p className="mt-1.5 flex-1 text-sm text-muted-foreground">{c.desc}</p>
                  <span className="mt-4 inline-flex items-center gap-1 font-mono text-xs text-brand-text opacity-0 transition-opacity group-hover:opacity-100">
                    Open <ArrowRight className="size-3" />
                  </span>
                </Link>
              </motion.div>
            ))}
          </div>
        </section>

        {/* API reference */}
        <motion.section {...fade(0.3)} className="pb-24">
          <APIDocumentation />
        </motion.section>
      </div>
    </div>
  );
}
