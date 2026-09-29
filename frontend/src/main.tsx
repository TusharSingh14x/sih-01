import React from 'react'
import ReactDOM from 'react-dom/client'
import './styles.css'

const container = document.getElementById('root')!
const root = ReactDOM.createRoot(container)
if (import.meta.env.VITE_DEMO_MODE === 'true') {
  void import('./DemoShowcase').then(({ default: DemoShowcase }) => root.render(<React.StrictMode><DemoShowcase /></React.StrictMode>))
} else {
  void import('./App').then(({ default: App }) => root.render(<React.StrictMode><App /></React.StrictMode>))
}
