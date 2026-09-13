import { useSyncExternalStore } from 'react'
import { applyTheme, getTheme, subscribeTheme, toggleTheme, type Theme } from '../stores/themeStore'

export function useTheme() {
  const theme = useSyncExternalStore(subscribeTheme, getTheme, () => 'dark' as Theme)

  return {
    theme,
    setTheme: applyTheme,
    toggleTheme,
    isDark: theme === 'dark',
    isLight: theme === 'light',
  }
}
