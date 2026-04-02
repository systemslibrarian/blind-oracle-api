const express = require('express')
const { getSealRuntime } = require('../sealContext')

const router = express.Router()

function previewCiphertext(value) {
  if (typeof value !== 'string') {
    return 'invalid'
  }
  return `${value.slice(0, 12)}...`
}

router.use((req, res, next) => {
  const started = Date.now()
  const ctAPreview = previewCiphertext(req.body?.ctA)
  const ctBPreview = previewCiphertext(req.body?.ctB)

  res.on('finish', () => {
    const ts = new Date().toISOString()
    const elapsed = Date.now() - started
    console.log(
      `[${ts}] POST /compute/add - ct_a: ${ctAPreview} ct_b: ${ctBPreview} -> ${res.statusCode} (${elapsed}ms)`
    )
  })

  next()
})

router.post('/add', (req, res) => {
  const runtime = getSealRuntime()

  if (!runtime.ready) {
    return res.status(503).json({ error: 'Oracle initializing' })
  }

  const { ctA, ctB } = req.body || {}
  if (typeof ctA !== 'string' || typeof ctB !== 'string' || !ctA || !ctB) {
    return res.status(400).json({
      error: 'Invalid ciphertext',
      plaintextAccessed: false
    })
  }

  try {
    const cipherA = runtime.seal.CipherText()
    const cipherB = runtime.seal.CipherText()
    const cipherResult = runtime.seal.CipherText()

    cipherA.load(runtime.context, ctA)
    cipherB.load(runtime.context, ctB)

    runtime.evaluator.add(cipherA, cipherB, cipherResult)

    return res.status(200).json({
      ctResult: cipherResult.save(),
      operation: 'homomorphic_add',
      plaintextAccessed: false,
      serverKeyType: 'evaluation_only'
    })
  } catch (error) {
    console.error('[ORACLE] Compute failure:', error.message)
    return res.status(400).json({
      error: 'Invalid ciphertext',
      plaintextAccessed: false
    })
  }
})

module.exports = router
