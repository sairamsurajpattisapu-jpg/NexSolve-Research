export type Theme = 'dark' | 'light'

export const THEME_STORAGE_KEY = 'nexsolve-theme'

function getInitialTheme(): Theme {
  if (typeof window === 'undefined') return 'dark'
  try {
    const stored = localStorage.getItem(THEME_STORAGE_KEY)
    if (stored === 'light' || stored === 'dark') return stored
  } catch {
    // localStorage not accessible
  }
  return 'dark'
}

let currentTheme: Theme = getInitialTheme()
const listeners = new Set<(theme: Theme) => void>()

if (typeof document !== 'undefined') {
  document.documentElement.setAttribute('data-theme', currentTheme)
  document.documentElement.style.colorScheme = currentTheme
}

if (typeof window !== 'undefined') {
  window.addEventListener('storage', (e) => {
    if (e.key === THEME_STORAGE_KEY && (e.newValue === 'light' || e.newValue === 'dark')) {
      currentTheme = e.newValue
      document.documentElement.setAttribute('data-theme', e.newValue)
      document.documentElement.style.colorScheme = e.newValue
      listeners.forEach((fn) => fn(e.newValue as Theme))
    }
  })
}

export function applyTheme(theme: Theme) {
  currentTheme = theme
  if (typeof document !== 'undefined') {
    document.documentElement.setAttribute('data-theme', theme)
    document.documentElement.style.colorScheme = theme
  }
  try {
    localStorage.setItem(THEME_STORAGE_KEY, theme)
  } catch {
    // ignore storage write issues
  }
  listeners.forEach((fn) => fn(theme))
}

export function toggleTheme(): Theme {
  const next = currentTheme === 'dark' ? 'light' : 'dark'
  applyTheme(next)
  return next
}

export function getTheme(): Theme {
  return currentTheme
}

export function subscribeTheme(listener: (theme: Theme) => void) {
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}
