import { IAgentPlugin } from '@veramo/core'
import {
  IEbsiPlugin,
  ICreateIdentifierV1Args,
  IRequiredContext,
  IVerifiableAuthorization,
  IRequestVerifiableAuthorizationArgs,
  IAccessToken,
  IExchangeVerifiableAuthorizationArgs,
  ICreateVerifiablePresentationArgs,
  IVerifiablePresentation,
} from '../types/IEbsiPlugin'
import { IIdentifier } from '@veramo/core'
import { base58btc } from 'multiformats/bases/base58'
import {
  bytesToBase64url,
  bytesToHex,
  extractPublicKeyBytes,
  getUncompressedPublicKey,
  hexToBytes,
} from '../utils/key-utils'
import elliptic from 'elliptic'
import { randomBytes } from 'crypto'
import * as jose from 'jose'
import { v4 as uuidv4 } from 'uuid'
import { Agent } from '@cef-ebsi/siop-auth'
import {
  createVerifiablePresentationJwt,
  EbsiIssuer,
  EbsiVerifiablePresentation,
} from '@cef-ebsi/verifiable-presentation'

/**
 * {@inheritDoc IEbsiPlugin}
 * @beta
 */
export class EbsiPlugin implements IAgentPlugin {
  // map the methods your plugin is declaring to their implementation
  readonly methods: IEbsiPlugin = {
    createIdentifierV1: this.createIdentifierV1.bind(this),
    requestVerifiableAuthorization: this.requestVerifiableAuthorization.bind(this),
    exchangeVerifiableAuthorization: this.exchangeVerifiableAuthorization.bind(this),
    createVerifiablePresentation: this.createVerifiablePresentation.bind(this),
  }

  // list the event types that this plugin cares about.
  // When the agent emits an event of these types, `MyAgentPlugin.onEvent()` will get called.
  readonly eventTypes = ['validatedMessage']

  // the event handler for the types listed in `eventTypes`
  public async onEvent(event: { type: string; data: any }, context: IRequiredContext) {
    // you can emit other events
    await context.agent.emit('my-event', { foo: event.data.id })
    // or call other agent methods that are declared in the context
    const allDIDs = await context.agent.didManagerFind()
  }

  private async createIdentifierV1(
    args: ICreateIdentifierV1Args,
    context: IRequiredContext
  ): Promise<Omit<IIdentifier, 'provider'>> {
    const keys = await jose.generateKeyPair('ES256K')
    const privateKeyJwk = await jose.exportJWK(keys.privateKey)
    if (!privateKeyJwk.d) {
      throw new Error('There has been an error while generating keys')
    }

    const privateKeyHex = Buffer.from(privateKeyJwk.d, 'base64').toString('hex')
    const key = await context.agent.keyManagerImport({
      privateKeyHex: privateKeyHex,
      type: 'Secp256k1',
      kms: args.kms || 'local',
    })

    let bytes = extractPublicKeyBytes({ controller: '', id: '', ...key })
    let hex = bytesToHex(bytes)
    if (hex.substring(0, 2) === '02' || hex.substring(0, 2) === '03') {
      hex = getUncompressedPublicKey(hex as string)
      bytes = hexToBytes(hex)
    }

    const ec = new elliptic.ec('secp256k1')
    const pubPoint = ec.keyFromPublic(bytes).getPublic()
    const publicKeyJwk = {
      kty: 'EC',
      x: bytesToBase64url(pubPoint.getX().toBuffer('be', 32)),
      y: bytesToBase64url(pubPoint.getY().toBuffer('be', 32)),
      crv: 'secp256k1',
      use: 'sig',
      alg: 'ES256K',
    }

    const jwkThumbprint = await jose.calculateJwkThumbprint(
      { kty: 'EC', crv: 'secp256k1', x: publicKeyJwk.x, y: publicKeyJwk.y },
      'sha256'
    )
    const subjectIdentifier = Buffer.from(
      base58btc.encode(Buffer.concat([new Uint8Array([1]), randomBytes(16)]))
    ).toString()

    const kid = `did:ebsi:${subjectIdentifier}#${jwkThumbprint}`
    const did = `did:ebsi:${subjectIdentifier}`

    const identifier: Omit<IIdentifier, 'provider'> = {
      did,
      controllerKeyId: kid,
      keys: [key],
      services: [],
    }
    identifier.keys[0].privateKeyHex = privateKeyHex

    const didDocument = {
      '@context': 'https://w3id.org/did/v1',
      id: did,
      verificationMethod: [
        {
          id: kid,
          type: 'JsonWebKey2020',
          controller: did,
          publicKeyJwk,
        },
      ],
      authentication: [kid],
      assertionMethod: [kid],
    }

    const bearer =
      'eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QiLCJraWQiOiJkaWQ6ZWJzaTp6cjJyV0RISHJVQ2RaQVc3d3NTYjVuUSNrZXlzLTEifQ.eyJvbmJvYXJkaW5nIjoicmVjYXB0Y2hhIiwidmFsaWRhdGVkSW5mbyI6eyJzdWNjZXNzIjp0cnVlLCJjaGFsbGVuZ2VfdHMiOiIyMDIzLTAyLTIxVDAyOjA1OjA2WiIsImhvc3RuYW1lIjoiYXBwLXBpbG90LmVic2kuZXUiLCJzY29yZSI6MC45LCJhY3Rpb24iOiJsb2dpbiJ9LCJpc3MiOiJkaWQ6ZWJzaTp6cjJyV0RISHJVQ2RaQVc3d3NTYjVuUSIsImlhdCI6MTY3Njk0NTMyNiwiZXhwIjoxNjc2OTQ2MjI2fQ.YZrq7vushN8yU49kCiWl7igYUZSbeZJlGFeiL4j9U1NVX_oYeMStPLBBdk9hi62Dcw0Nasxvh2IOeWmrLg_J1g'
    const verifiableAuthorization = await this.requestVerifiableAuthorization({
      kid,
      publicKeyJwk,
      privateKeyJwk,
      bearer,
    })

    const verifiablePresentation = await this.createVerifiablePresentation({
      verifiableAuthorization,
      privateKeyJwk,
      publicKeyJwk,
      identifier,
    })

    const accessToken = await this.exchangeVerifiableAuthorization({
      verifiablePresentation,
      privateKeyJwk,
      publicKeyJwk,
      identifier,
    })

    if (identifier.keys[0].privateKeyHex) {
      delete identifier.keys[0].privateKeyHex
    }
    return identifier
  }

  private async requestVerifiableAuthorization(
    args: IRequestVerifiableAuthorizationArgs
  ): Promise<IVerifiableAuthorization> {
    const subject = args.kid.split('#')[1]
    const idToken = {
      sub: subject,
      sub_jwk: args.publicKeyJwk,
      nonce: uuidv4(),
      responseMode: 'form_post',
    }

    const privateKey = await jose.importJWK(args.privateKeyJwk, 'ES256K')
    const idTokenJwt = await new jose.SignJWT(idToken)
      .setProtectedHeader({ alg: 'ES256K', typ: 'JWT', kid: args.kid })
      .setIssuedAt()
      .setAudience('https://api-pilot.ebsi.eu/users-onboarding/v2/authentication-responses')
      .setIssuer('https://self-issued.me/v2')
      .setExpirationTime('1h')
      .sign(privateKey)

    const authenticationResponse = await fetch(
      'https://api-pilot.ebsi.eu/users-onboarding/v2/authentication-responses',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${args.bearer}`,
        },
        body: JSON.stringify({
          id_token: idTokenJwt,
        }),
      }
    )

    const va = await authenticationResponse.json()
    if (authenticationResponse.status > 299 || authenticationResponse.status < 200) {
      throw new Error(`${JSON.stringify(va, null, 2)}`)
    }

    return va
  }

  private async createVerifiablePresentation(
    args: ICreateVerifiablePresentationArgs
  ): Promise<IVerifiablePresentation> {
    const verifiableAuthorization = args.verifiableAuthorization.verifiableCredential
    if (args.identifier.controllerKeyId === undefined) {
      throw new Error('Controller Key ID undefined')
    }
    if (args.verifiableAuthorization.verifiableCredential === undefined) {
      throw new Error('Verifiable Authorization undefined')
    }

    const issuer: EbsiIssuer = {
      did: args.identifier.did,
      kid: args.identifier.controllerKeyId,
      privateKeyJwk: args.privateKeyJwk,
      publicKeyJwk: args.publicKeyJwk,
      alg: 'ES256K',
    }

    const payload = {
      id: `urn:did:${uuidv4()}`,
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiablePresentation'],
      holder: args.identifier.did,
      verifiableCredential: [verifiableAuthorization as string],
    } as EbsiVerifiablePresentation
    const jwtVp = await createVerifiablePresentationJwt(
      payload,
      issuer,
      'https://api-pilot.ebsi.eu/authorisation/v2/siop-sessions',
      {
        skipValidation: true,
        ebsiAuthority: 'api-pilot.ebsi.eu'.replace('http://', '').replace('https://', ''),
        exp: Math.floor(Date.now() / 1000) + 900,
      }
    )

    return { jwtVp, payload }
  }

  private async exchangeVerifiableAuthorization(args: IExchangeVerifiableAuthorizationArgs): Promise<IAccessToken> {
    const agent = new Agent({
      privateKey: await jose.importJWK(args.privateKeyJwk, 'ES256K'),
      alg: 'ES256K',
      kid: args.identifier.controllerKeyId,
      siopV2: true,
    })
    const response = await agent.createResponse({
      nonce: uuidv4(),
      redirectUri: 'https://example.com',
      claims: {
        encryption_key: args.publicKeyJwk,
      },
      responseMode: 'form_post',
      _vp_token: {
        presentation_submission: {
          id: uuidv4(),
          definition_id: uuidv4(),
          descriptor_map: [
            {
              id: uuidv4(),
              format: 'jwt_vp',
              path: '$',
              path_nested: {
                id: 'onboarding-input-id',
                format: 'jwt_vc',
                path: '$.vp.verifiableCredential[0]',
              },
            },
          ],
        },
      },
    })

    const body = {
      id_token: response.idToken as string,
      vp_token: args.verifiablePresentation.jwtVp as string,
    }
    const callback = 'https://api-pilot.ebsi.eu/authorisation/v2/siop-sessions'
    const sessionResponse = await fetch(callback, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams(body),
    })
    const session = await sessionResponse.json()

    if (sessionResponse.status > 299 || sessionResponse.status < 200) {
      throw new Error(`${JSON.stringify(session, null, 2)}`)
    }

    return session
  }

  /** {@inheritDoc IMyAgentPlugin.myPluginFoo} */
  // private async ebsiPluginFoo(args: IEbsiPluginFooArgs, context: IRequiredContext): Promise<IMyAgentPluginFooResult> {
  //   // you can call other agent methods (that are declared in the `IRequiredContext`)
  //   const didDoc = await context.agent.resolveDid({ didUrl: args.did })
  //   // or emit some events
  //   await context.agent.emit('my-other-event', { foo: 'hello' })
  //   return { foobar: args.bar }
  // }
}
