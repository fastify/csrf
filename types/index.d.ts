interface TokensBase {
  /**
   * Create a new secret key.
   */
   secret(callback: SecretCallback): void;
   secret(): Promise<string>;

  /**
   * Create a new secret key synchronously.
   */
  secretSync(): string;
}

interface TokensSimple extends TokensBase {
  /**
   * Create a new CSRF token.
   */
  create(secret: string): string;

  /**
   * Verify if a given token is valid for a given secret.
   */
  verify(secret: string, token: string): boolean;
}

interface TokensUserinfo extends TokensBase {
  /**
   * Create a new CSRF token.
   */
  create(secret: string, userInfo: string): string;

  /**
   * Verify if a given token is valid for a given secret.
   */
  verify(secret: string, token: string, userInfo: string): boolean;
}

export type SecretCallback = (err: Error | null, secret: string) => void;

export interface Options {
  /**
   * The string length of the salt
   * 
   * @default 8
   */
  saltLength?: number;
  /**
   * The byte length of the secret key
   * 
   * @default 18
   */
  secretLength?: number;

  /**
   * The maximum milliseconds of validity of this token. 0 disables the check.
   * 
   * @default 0
   */
  validity?: number;

  /**
   * Require userInfo on create() and verify()
   * 
   * @default false
   */
  userInfo?: boolean;
}

export const Tokens: TokensConstructor;
export default Tokens;

export interface TokensConstructor {
  (options?: Options & { userInfo: true}): TokensUserinfo;
  (options?: Options): TokensSimple;

  new(options?: Options & { userInfo: true}): TokensUserinfo;
  new(options?: Options): TokensSimple;
}