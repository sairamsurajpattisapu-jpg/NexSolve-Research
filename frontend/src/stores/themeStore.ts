export type Theme = 'dark' | 'light'

export const THEME_STORAGE_KEY = 'nexsolve-theme'

// Permanent dark theme for NexSolve
const PERMANENT_THEME: Theme = 'dark'

if (typeof window !== 'undefined') {
  try {
    // Clear any legacy light-theme preference from localStorage
    localStorage.removeItem(THEME_STORAGE_KEY)
  } catch {
    // ignore
  }
}

if (typeof document !== 'undefined') {
  document.documentElement.setAttribute('data-theme', PERMANENT_THEME)
  document.documentElement.style.colorScheme = PERMANENT_THEME
}

export function applyTheme(_theme: Theme) {
  // Theme is permanently dark
  if (typeof document !== 'undefined') {
    document.documentElement.setAttribute('data-theme', PERMANENT_THEME)
    document.documentElement.style.colorScheme = PERMANENT_THEME
  }
}

export function toggleTheme(): Theme {
  return PERMANENT_THEME
}

export function getTheme(): Theme {
  return PERMANENT_THEME
}

export function subscribeTheme(_listener: (theme: Theme) => void) {
  return () => {}
}
