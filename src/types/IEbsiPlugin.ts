import { EbsiVerifiablePresentation } from '@cef-ebsi/verifiable-presentation'
import { IPluginMethodMap, IAgentContext, IDIDManager, IResolver, IIdentifier, IKeyManager } from '@veramo/core'
import { JWK, KeyLike } from 'jose'

/**
 * My Agent Plugin description.
 *
 * This is the interface that describes what your plugin can do.
 * The methods listed here, will be directly available to the veramo agent where your plugin is going to be used.
 * Depending on the agent configuration, other agent plugins, as well as the application where the agent is used
 * will be able to call these methods.
 *
 * To build a schema for your plugin using standard tools, you must link to this file in package.json.
 * Example:
 * ```
 * "veramo": {
 *    "pluginInterfaces": {
 *      "IEBSILEPlugin": "./src/types/IMyAgentPlugin.ts"
 *    }
 *  },
 * ```
 *
 * @beta
 */
export interface IEbsiPlugin extends IPluginMethodMap {
  /**
   * Your plugin method description
   *
   * @param args - Input parameters for this method
   * @param context - The required context where this method can run.
   *   Declaring a context type here lets other developers know which other plugins
   *   need to also be installed for this method to work.
   */
  private createIdentifierV1(
    args: ICreateIdentifierV1Args,
    context: IRequiredContext
  ): Promise<Omit<IIdentifier, 'provider'>>
  private requestVerifiableAuthorization(
    args: IRequestVerifiableAuthorizationArgs,
    context: IRequiredContext
  ): Promise<IVerifiableAuthorization>
  private createVerifiablePresentation(
    args: ICreateVerifiablePresentationArgscontext,
    context: IRequiredContext
  ): Promise<IVerifiablePresentation>
  private exchangeVerifiableAuthorization(
    args: IExchangeVerifiableAuthorizationArgscontext,
    context: IRequiredContext
  ): Promise<IAccessToken>
  private insertDidDocument(args: IInsertDidDocumentArgscontext, context: IRequiredContext): Promise<IRPCResult>
}

/**
 * Arguments needed for {@link EbsiPlugin.createIdentifierV1}
 * To be able to export a plugin schema, your plugin methods should use an `args` parameter of a
 * named type or interface.
 *
 * @beta
 */
export interface ICreateIdentifierV1Args {
  /**
   * Key Management System
   */
  kms?: string

  /**
   * Additional options
   */
  options?: any
}

export interface IRequestVerifiableAuthorizationArgs {
  /**
   * JWT encoded id token
   */
  idTokenJwt: string
  /**
   * Bearer token needed for authorization
   */
  bearer: string
}

export interface IVerifiableAuthorization {
  /**
   * JWT encoded Verifiable Authorization
   */
  verifiableCredential: string
}

export interface ICreateVerifiablePresentationArgs {
  /**
   * Verifiable Authorization in form of a Verifiable Credential
   */
  verifiableAuthorization: IVerifiableAuthorization
  /**
   * Identifier to be used for setting up the EbsiIssuer
   */
  identifier: Omit<IIdentifier, 'provider'>
  /**
   * Private key in JWK format
   */
  privateKeyJwk: JWK
  /**
   * Public key in JWK format
   */
  publicKeyJwk: JWK
}

export interface IVerifiablePresentation {
  /**
   * JWT encoded Verifiable Presentation
   */
  jwtVp: string
  /**
   * Payload of the Verifiable Presentation
   */
  payload: EbsiVerifiablePresentation
}

export interface IExchangeVerifiableAuthorizationArgs {
  /**
   * JWT encoded Verifiable Authorization
   */
  verifiablePresentation: any
  /**
   * Identifier to be used for setting up the SiopAgent
   */
  identifier: Omit<IIdentifier, 'provider'>
  /**
   * Private key in JWK format
   */
  privateKeyJwk: JWK
  /**
   * Public key in JWK format
   */
  publicKeyJwk: JWK
}

export interface IAccessToken {
  /**
   * Encrypted payload with user's public key
   */
  ake1_enc_payload: string
  /**
   * Encrypted payload with user's public key
   */
  ake1_sig_payload: ISIOPSessionPayload
  /**
   * Detached JWS of AKE1 Signing Payload
   */
  ake1_jws_detached: string
  /**
   * API KID
   */
  kid: string
}

export interface ISIOPSessionPayload {
  /**
   * Issued at
   */
  iat: number
  /**
   * Expires at
   */
  exp: number
  /**
   * Nonce used during the authentication process
   */
  ake1_nonce: string
  /**
   * Encrypted payload with user's public key
   */
  ake1_enc_payload: string
  /**
   * API DID
   */
  did: string
  /**
   * Issuer
   */
  iss: string
}

export interface IInsertDidDocumentArgs {
  /**
   * Bearer token needed for authorization
   */
  bearer: string
  /**
   * Identifier needed to generate a DID Document which will be
   * inserted into the EBSI DID registry
   */
  identifier: Omit<IIdentifier, 'provider'>
  /**
   * Public key in JWK format used to sign the DID Document
   */
  publicKeyJwk: JWK
}

export interface IRPCResult {
  /**
   * Must be exactly "2.0"
   */
  jsonrpc: string
  /**
   * Same identifier established by the client in the call
   */
  id: integer
  /**
   * Result of the call
   */
  result: string | object
}

/**
 * This context describes the requirements of this plugin.
 * For this plugin to function properly, the agent needs to also have other plugins installed that implement the
 * interfaces declared here.
 * You can also define requirements on a more granular level, for each plugin method or event handler of your plugin.
 *
 * @beta
 */
export type IRequiredContext = IAgentContext<IResolver & IDIDManager & IKeyManager>
