import { EbsiVerifiablePresentation } from '@cef-ebsi/verifiable-presentation';
import { IPluginMethodMap, IAgentContext, IDIDManager, IResolver, IIdentifier, IKeyManager } from '@veramo/core'
import { JWK, KeyLike } from 'jose';

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
  private createIdentifierV1(args: ICreateIdentifierV1Args, context: IRequiredContext): Promise<Omit<IIdentifier, "provider">>;
  private requestVerifiableAuthorization(args: IRequestVerifiableAuthorizationArgs): Promise<IVerifiableAuthorization>;
  private exchangeVerifiableAuthorization(args: IExchangeVerifiableAuthorizationArgs): Promise<IAccessToken>;

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
   * Bearer token needed for authorization
   */
  bearer: string
}

export interface IExchangeVerifiableAuthorizationArgs {
  /**
   * JWT encoded Verifiable Authorization
   */
  verifiablePresentation: any
  /**
   * Identifier to be used for setting up the SiopAgent
   */
  identifier: Omit<IIdentifier, "provider">
  /**
   * Private key in JWK format
   */
  privateKeyJwk: JWK
  /**
   * Public key in JWK format
   */
  publicKeyJwk: JWK
}

export interface ICreateVerifiablePresentationArgs {
  /**
   * Verifiable Authorization in form of a Verifiable Credential
   */
  verifiableAuthorization: IVerifiableAuthorization
  /**
   * Identifier to be used for setting up the EbsiIssuer
   */
  identifier: Omit<IIdentifier, "provider">
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

export interface IAccessToken {
  /**
   * Access token returned by exchange of Verifiable Authorization
   */
  accessToken: string
}

export interface IVerifiableAuthorization {
  /**
   * JWT encoded Verifiable Authorization
   */
  verifiableCredential: string
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
