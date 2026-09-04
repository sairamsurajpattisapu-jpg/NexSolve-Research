import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { Layout } from '../components/Layout'

function renderLayout(path = '/dashboard') {
  return render(<MemoryRouter initialEntries={[path]}><Routes><Route element={<Layout status="API connected" />}><Route path="*" element={<div>Route content</div>} /></Route></Routes></MemoryRouter>)
}

describe('application navigation', () => {
  it('renders the navigation and supports keyboard-usable route links', async () => {
    const user = userEvent.setup()
    renderLayout()
    await user.click(screen.getByRole('link', { name: 'Threats' }))
    expect(screen.getByRole('link', { name: 'Threats' })).toHaveClass('active')
  })

  it('opens and closes mobile navigation', async () => {
    const user = userEvent.setup()
    renderLayout()
    await user.click(screen.getByRole('button', { name: 'Open navigation' }))
    expect(screen.getAllByRole('button', { name: 'Close navigation' })).toHaveLength(2)
    await user.click(screen.getAllByRole('button', { name: 'Close navigation' })[1])
    expect(screen.getByRole('button', { name: 'Open navigation' })).toBeInTheDocument()
  })
})
