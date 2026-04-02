const express = require('express')
const cors = require('cors')
const computeRouter = require('./src/routes/compute')
const { initSeal, getSealRuntime } = require('./src/sealContext')

const PORT = process.env.PORT || 3001
const ORIGIN = 'https://systemslibrarian.github.io'

const app = express()
app.use(express.json({ limit: '1mb' }))
app.use(
  cors({
    origin: ORIGIN,
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type']
  })
)

app.get('/health', (_req, res) => {
  const runtime = getSealRuntime()
  res.status(200).json({
    status: 'ok',
    seal: runtime.ready ? 'ready' : 'initializing'
  })
})

app.use('/compute', computeRouter)

async function start() {
  try {
    await initSeal()
    app.listen(PORT, () => {
      console.log(`[HTTP] blind-oracle-api listening on ${PORT}`)
    })
  } catch (error) {
    console.error('[BOOT] Failed to initialize service:', error)
    process.exit(1)
  }
}

start()
