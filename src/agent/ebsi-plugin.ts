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
    // Generating a key pair with jose to get a private key for later use
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
      use: "sig",
      crv: 'Secp256k1',
      x: bytesToBase64url(pubPoint.getX().toBuffer('be', 32)),
      y: bytesToBase64url(pubPoint.getY().toBuffer('be', 32)),
      alg: 'ES256K',
    }

    const jwkThumbprint = await jose.calculateJwkThumbprint(
      { kty: 'EC', crv: 'Secp256k1', x: publicKeyJwk.x, y: publicKeyJwk.y },
      'sha256'
    )
    const subjectIdentifier = Buffer.from(
      base58btc.encode(Buffer.concat([new Uint8Array([1]), randomBytes(16)]))
    ).toString()
    // const subIdentifierBuffer = Buffer.concat([Buffer.from('01'), randomBytes(16)])
    console.log(subjectIdentifier)
    // const base58 = base58btc.encode(subIdentifierBuffer)
    // console.log(subIden.toString())
    const kid = `did:ebsi:${subjectIdentifier}#${jwkThumbprint}`
    const did = `did:ebsi:${subjectIdentifier}`

    const identifier: Omit<IIdentifier, 'provider'> = {
      did,
      controllerKeyId: kid,
      keys: [key],
      services: [],
    }
    identifier.keys[0].privateKeyHex = privateKeyHex
    console.log('identifier', identifier)

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

    console.log(didDocument)
    console.log(didDocument.verificationMethod[0].publicKeyJwk)
    const bearer =
      'eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QiLCJraWQiOiJkaWQ6ZWJzaTp6cjJyV0RISHJVQ2RaQVc3d3NTYjVuUSNrZXlzLTEifQ.eyJvbmJvYXJkaW5nIjoicmVjYXB0Y2hhIiwidmFsaWRhdGVkSW5mbyI6eyJzdWNjZXNzIjp0cnVlLCJjaGFsbGVuZ2VfdHMiOiIyMDIzLTAyLTA3VDE0OjE3OjUyWiIsImhvc3RuYW1lIjoiYXBwLXBpbG90LmVic2kuZXUiLCJzY29yZSI6MC4zLCJhY3Rpb24iOiJsb2dpbiJ9LCJpc3MiOiJkaWQ6ZWJzaTp6cjJyV0RISHJVQ2RaQVc3d3NTYjVuUSIsImlhdCI6MTY3NTc4MTQwMywiZXhwIjoxNjc1NzgyMzAzfQ.vna7SEsdCkGrxzrQAkCWNRVWn7JMce3tOVu3t-CYmkuw83GJ51atfTg1YnV1YvUpbliQ3A22DQdo-oVMxCeNNw'
    const verifiableAuthorization = await this.requestVerifiableAuthorization({ bearer: bearer })
    const verifiablePresentation = await this.createVerifiablePresentation({
      verifiableAuthorization,
      privateKeyJwk,
      publicKeyJwk,
      identifier,
    })
    console.log(verifiablePresentation)
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
    // const request = new URLSearchParams((await authenticationRequest.json())['session_token'])
    const authenticationResponse = await fetch(
      'https://api-pilot.ebsi.eu/users-onboarding/v2/authentication-responses',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${args.bearer}`,
        },
        body: JSON.stringify({
          id_token: args.bearer,
        }),
      }
    )
    // return await authenticationResponse.json();
    return {
      verifiableCredential:
        'eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QiLCJraWQiOiJkaWQ6ZWJzaTp6cjJyV0RISHJVQ2RaQVc3d3NTYjVuUSNrZXlzLTEifQ.eyJqdGkiOiJ2YzplYnNpOmF1dGhlbnRpY2F0aW9uIzU3OWFlYTRhLTdmMGYtNDFkMS1iYTBjLTE0NzAxMTZiYTE3MSIsInN1YiI6ImRpZDplYnNpOnpyMnJXREhIclVDZFpBVzd3c1NiNW5RIiwiaXNzIjoiZGlkOmVic2k6enIycldESEhyVUNkWkFXN3dzU2I1blEiLCJuYmYiOjE2NzU3Nzk2MjIsImV4cCI6MTY5MTUwNDQyMiwiaWF0IjoxNjc1Nzc5NjIyLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJpZCI6InZjOmVic2k6YXV0aGVudGljYXRpb24jNTc5YWVhNGEtN2YwZi00MWQxLWJhMGMtMTQ3MDExNmJhMTcxIiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlZlcmlmaWFibGVBdXRob3Jpc2F0aW9uIl0sImlzc3VlciI6ImRpZDplYnNpOnpyMnJXREhIclVDZFpBVzd3c1NiNW5RIiwiaXNzdWFuY2VEYXRlIjoiMjAyMy0wMi0wN1QxNDoyMDoyMloiLCJpc3N1ZWQiOiIyMDIzLTAyLTA3VDE0OjIwOjIyWiIsInZhbGlkRnJvbSI6IjIwMjMtMDItMDdUMTQ6MjA6MjJaIiwiZXhwaXJhdGlvbkRhdGUiOiIyMDIzLTA4LTA4VDE0OjIwOjIyWiIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmVic2k6enIycldESEhyVUNkWkFXN3dzU2I1blEifSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6Imh0dHBzOi8vYXBpLXBpbG90LmVic2kuZXUvdHJ1c3RlZC1zY2hlbWFzLXJlZ2lzdHJ5L3YyL3NjaGVtYXMvejNNZ1VGVWtiNzIydXE0eDNkdjV5QUptbk5tekRGZUs1VUM4eDgzUW9lTEpNIiwidHlwZSI6IkZ1bGxKc29uU2NoZW1hVmFsaWRhdG9yMjAyMSJ9fX0.zt6ftDhJnf8APYt9BMz0cTwDHAob6a2AbBOFOVXXOK9vgTeOx8W81VoHZDVVM3Xz6FkZfsh-uiO89hEbRugsOg',
    }
  }

  private async createVerifiablePresentation(
    args: ICreateVerifiablePresentationArgs
  ): Promise<IVerifiablePresentation> {
    const verifiableAuthorization = args.verifiableAuthorization.verifiableCredential
    if (args.identifier.controllerKeyId === undefined) {
      throw new Error()
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

  // TODO: initiate a SIOP request
  // post to https://api-pilot.ebsi.eu/authorisation/v2/authentication-requests
  // with body: { "scope": openid did_authn}
  // save response to "res"
  private async exchangeVerifiableAuthorization(args: IExchangeVerifiableAuthorizationArgs): Promise<IAccessToken> {
    const siopUri = await fetch('https://api-pilot.ebsi.eu/authorisation/v2/authentication-requests', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        scope: 'openid did_authn',
      }),
    })
    const siopRequestParams = new URLSearchParams(await siopUri.text())
    const siopRequestJwt = siopRequestParams.get('request')
    if (!siopRequestJwt) {
      throw new Error('No SIOP request found')
    }

    const agent = new Agent({
      privateKey: await jose.importJWK(args.privateKeyJwk, 'ES256K'),
      alg: 'ES256K',
      kid: args.identifier.keys[0].kid,
      siopV2: true,
    })

    const idToken = agent.createResponse({
      nonce: uuidv4(),
      redirectUri: 'https://test.com',
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
      id_token: idToken,
      vp_token: args.verifiablePresentation,
    }

    const siopSessionRequestBody = {
      id_token: idToken,
      vp_token: '',
    }

    return { accessToken: 'requestJwt' }
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
