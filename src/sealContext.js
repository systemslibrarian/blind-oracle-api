const SEAL = require('node-seal')
const params = require('./sealParams')

const sealRuntime = {
  seal: null,
  context: null,
  evaluator: null,
  encoder: null,
  ready: false
}

async function initSeal() {
  if (sealRuntime.ready) {
    return sealRuntime
  }

  console.log('[SEAL] Initializing Microsoft SEAL context...')

  const seal = await SEAL()
  const schemeType =
    seal.SchemeType[params.scheme] ??
    seal.SchemeType[String(params.scheme).toLowerCase()] ??
    seal.SchemeType[String(params.scheme).toUpperCase()]
  if (!schemeType) {
    throw new Error(`Unsupported scheme enum: ${params.scheme}`)
  }
  const encryptionParameters = seal.EncryptionParameters(schemeType)

  encryptionParameters.setPolyModulusDegree(params.polyModulusDegree)
  encryptionParameters.setCoeffModulus(
    seal.CoeffModulus.BFVDefault(params.polyModulusDegree)
  )
  encryptionParameters.setPlainModulus(
    seal.PlainModulus.Batching(params.polyModulusDegree, params.plainModulusBitSize)
  )

  const securityLevel =
    seal.SecurityLevel[params.securityLevel] ??
    seal.SecurityLevel[String(params.securityLevel).toLowerCase()] ??
    seal.SecurityLevel[String(params.securityLevel).toUpperCase()]
  if (!securityLevel) {
    throw new Error(`Unsupported security level enum: ${params.securityLevel}`)
  }

  const context = seal.Context(encryptionParameters, true, securityLevel)

  if (!context.parametersSet()) {
    throw new Error('Invalid SEAL BFV parameters for context creation')
  }

  sealRuntime.seal = seal
  sealRuntime.context = context
  sealRuntime.evaluator = seal.Evaluator(context)
  sealRuntime.encoder = seal.BatchEncoder(context)
  sealRuntime.ready = true

  console.log('[SEAL] Context ready. Evaluator armed. No private key held.')
  return sealRuntime
}

function getSealRuntime() {
  return sealRuntime
}

module.exports = {
  initSeal,
  getSealRuntime
}
