import { motion, AnimatePresence } from 'motion/react';
import { Keyboard, X } from 'lucide-react';
import { formatShortcut, type Shortcut } from '../hooks/useKeyboardShortcuts';

interface Props {
  open: boolean;
  onClose: () => void;
  shortcuts: Shortcut[];
}

/** Modal overlay listing all registered shortcuts, grouped. Dismiss with
 *  Escape or backdrop click. The intent is "press ? to remember what `r`
 *  does" — keep it scannable, not exhaustive. */
export function ShortcutsCheatsheet({ open, onClose, shortcuts }: Props) {
  const grouped = shortcuts.reduce<Record<string, Shortcut[]>>((acc, s) => {
    const g = s.group ?? 'General';
    (acc[g] ??= []).push(s);
    return acc;
  }, {});

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.15 }}
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4"
          onClick={onClose}
        >
          <motion.div
            initial={{ opacity: 0, scale: 0.96, y: 8 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.96, y: 8 }}
            transition={{ duration: 0.15 }}
            onClick={(e) => e.stopPropagation()}
            className="bg-[#0f1825] border border-[#1a2540] rounded-xl shadow-2xl w-full max-w-2xl max-h-[80vh] overflow-y-auto"
          >
            <div className="flex items-center justify-between p-4 border-b border-[#1a2540] sticky top-0 bg-[#0f1825]">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Keyboard className="w-4 h-4 text-[#00ccff]" />
                Keyboard shortcuts
              </h3>
              <button
                type="button"
                onClick={onClose}
                className="text-gray-400 hover:text-white"
                aria-label="Close cheatsheet"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="p-4 space-y-5">
              {Object.entries(grouped).map(([group, items]) => (
                <div key={group}>
                  <div className="text-[10px] uppercase tracking-wide text-gray-500 mb-2">{group}</div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-1.5">
                    {items.map((s, i) => (
                      <div key={i} className="flex items-center justify-between gap-3 text-xs">
                        <span className="text-gray-300">{s.description ?? s.label ?? s.key}</span>
                        <kbd className="px-1.5 py-0.5 rounded border border-[#1a2540] bg-[#1a2540]/40 text-gray-200 font-mono text-[10px]">
                          {formatShortcut(s)}
                        </kbd>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
              <p className="text-[10px] text-gray-600 italic pt-2 border-t border-[#1a2540]">
                Shortcuts are ignored while a text input is focused (except Escape).
              </p>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
