// Minimal dependency-free structured logger (JSON lines). Levels gate on LOG_LEVEL
// (debug|info|warn|error, default info). Errors/warnings go to stderr, the rest to
// stdout — so log shipping and `2>` redirection both do the right thing.
type Level = 'debug' | 'info' | 'warn' | 'error'
const ORDER: Record<Level, number> = { debug: 10, info: 20, warn: 30, error: 40 }
const MIN = ORDER[(process.env.LOG_LEVEL as Level) ?? 'info'] ?? ORDER.info

function emit(level: Level, msg: string, fields?: Record<string, unknown>) {
  if (ORDER[level] < MIN) return
  const line = JSON.stringify({ ts: new Date().toISOString(), level, msg, ...fields })
  ;(level === 'error' || level === 'warn' ? process.stderr : process.stdout).write(line + '\n')
}

export const log = {
  debug: (msg: string, fields?: Record<string, unknown>) => emit('debug', msg, fields),
  info: (msg: string, fields?: Record<string, unknown>) => emit('info', msg, fields),
  warn: (msg: string, fields?: Record<string, unknown>) => emit('warn', msg, fields),
  error: (msg: string, fields?: Record<string, unknown>) => emit('error', msg, fields),
}
