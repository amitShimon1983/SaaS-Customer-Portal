import {
  IAuthenticateResponse,
  IConfig,
  OpenIdConfig,
  OpenIdKey,
  OpenIdKeys,
  Token,
  TokenHeader,
} from "../../entities";
import { HttpProvider } from "../httpProvider";
import { decode, verify } from "jsonwebtoken";
export class AuthenticationProvider {
  private static readonly _httpService: HttpProvider = new HttpProvider();
  private readonly _config: IConfig;
  constructor(config: IConfig) {
    this._config = config;
  }
  async validateRequest(token: string): Promise<boolean> {
    if (!token) {
      throw new Error("No token provided");
    }
    const tokenHeader: TokenHeader = this.extractTokenHeader(token);
    const { jwks_uri }: { jwks_uri: string } = await this.getJwksUri();
    if (jwks_uri) {
      const { keys }: { keys: OpenIdKey[] } = await this.getAzureJwtKeys(
        jwks_uri
      );
      if (keys?.length) {
        const matchKey: OpenIdKey = this.getMatchKey(keys, tokenHeader);
        return this.validateToken(matchKey.x5c[0], token);
      }
    }
  }
  private getMatchKey(keys: any, tokenHeader: TokenHeader): OpenIdKey {
    return keys.find(
      (key: OpenIdKey) =>
        key.kid === tokenHeader?.kid && key.x5t === tokenHeader?.kid
    );
  }

  validateToken(publicKey: string, token: string): boolean {
    const key: string = `-----BEGIN CERTIFICATE-----\n${publicKey}\n-----END CERTIFICATE-----`;
    try {
      return !!verify(token, key);
    } catch (error: any) {
      return false;
    }
  }

  private async getAzureJwtKeys(jwksUri: string): Promise<OpenIdKeys> {
    const openIdKeys: OpenIdKeys =
      await AuthenticationProvider._httpService.get<OpenIdKeys>(jwksUri);
    return openIdKeys;
  }

  private extractTokenHeader(token: string) {
    const tokenHeaderBase64 = token.split(".")[0];
    var buf = Buffer.from(tokenHeaderBase64, "base64");
    const tokenHeaderString = buf.toString("ascii");
    const tokenHeader: TokenHeader = JSON.parse(tokenHeaderString);
    return tokenHeader;
  }

  async acquireAppAuthenticationToken(): Promise<IAuthenticateResponse> {
    let authResponse: IAuthenticateResponse;
    try {
      authResponse =
        await AuthenticationProvider._httpService.post<IAuthenticateResponse>(
          this._config.authenticationUrl.replace(
            "*{tenantId}*",
            this._config.tenantId
          ),
          {
            headers: {
              Accept: "application/json",
              "Content-Type": "application/x-www-form-urlencoded",
            },
            body: new URLSearchParams({
              grant_type: "client_credentials",
              client_id: this._config.appClientId,
              client_secret: this._config.appClientSecret,
              resource: "20e940b3-4c77-4b0b-9a53-9e16a1b010a7",
            }).toString(),
          }
        );
    } catch (error: any) {
      throw error;
    }
    return authResponse;
  }
  async getJwksUri(): Promise<{ jwks_uri: string }> {
    return await AuthenticationProvider._httpService.get<OpenIdConfig>(
      "https://login.microsoftonline.com/common/.well-known/openid-configuration"
    );
  }
}
