import {
  AuthenticationResult,
  IAuthenticateResponse,
  IConfig,
  OpenIdConfig,
  OpenIdKey,
  OpenIdKeys,
  TokenHeader,
} from "../../entities";
import { HttpProvider } from "../httpProvider";
import { verify } from "jsonwebtoken";
import { HttpRequestHeaders } from "@azure/functions";
export class AuthenticationProvider {
  private static readonly _httpService: HttpProvider = new HttpProvider();
  private readonly _config: IConfig;
  constructor(config: IConfig) {
    this._config = config;
  }
  static async validateRequest(
    headers: HttpRequestHeaders
  ): Promise<AuthenticationResult> {
    const tokenReqHeader = headers?.authorization;
    //  || "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImpTMVhvMU9XRGpfNTJ2YndHTmd2UU8yVnpNYyJ9.eyJhdWQiOiI3NTg1ZjZmNy0xOWE3LTQ4YjQtYjIyZi04YjEzZDIyMGY2NDQiLCJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vMDMxMjI3MzctZjBkOC00ZjAwLWFlMzItNWZmMDg3YTNkYjhmL3YyLjAiLCJpYXQiOjE2NTM5MDc2OTcsIm5iZiI6MTY1MzkwNzY5NywiZXhwIjoxNjUzOTExNTk3LCJuYW1lIjoiQW1pdCBTaGltb24iLCJub25jZSI6ImM1MTQzYzdmLWJlOGMtNDhmZi1iMmY3LTAwMGYxNmYzNmMxZSIsIm9pZCI6ImI4ZmFmZmI5LTYwMjUtNGY1Yy1hYTEzLThiOTc1ZDQ3NzMxZSIsInByZWZlcnJlZF91c2VybmFtZSI6ImFtaXRzQGhhcm1vbi5pZSIsInJoIjoiMC5BVHNBTnljU0E5andBRS11TWxfd2g2UGJqX2YyaFhXbkdiUklzaS1MRTlJZzlrUTdBUDAuIiwic3ViIjoiVjhTYU5YOGMtZ3g5VkNSZ0hPaGtOZGVLbFU0dUdJLUwxOGhPZDlPMkRGcyIsInRpZCI6IjAzMTIyNzM3LWYwZDgtNGYwMC1hZTMyLTVmZjA4N2EzZGI4ZiIsInV0aSI6IjQzTm5ESkVNYmtlaUd5SjZlSWNzQUEiLCJ2ZXIiOiIyLjAifQ.EEcTSwGnRDh_Zxe02OaSCKE9kJtxKmrUBbBq56MqYo5u8UwjeuYaSjRM84hD7QTqmI3s99Ew4TJFbyPICF8GS92yXwGEFD1XhXNosO4gRq6-PgwSRsJ1m35qOWQd9ZqdKyPiHHsv75HHVmoCCloO0K0W4Bvvz9W3mXyKkN4gt5geFy6QwBzvc2v4nKf4q7wJIhHT_swl5eoFdZ6x6kDbyFidKO2_a2TDjhZzawUJOSB1tcNRhBx3yJPHjIyIEgv7I0-3YpfGawcuCOtPtqR02VFUDcROt_DS0PW-sLKyiEmtjDg5E_CqmLMcYjGcM5zRaUjG5a3JpIeiiFvcLaJCtg";
    if (!tokenReqHeader) {
      return {
        status: 401,
        isAuthenticate: false,
        message: "User need to authenticate",
      } as AuthenticationResult;
    }
    const token: string = tokenReqHeader?.replace("Bearer ", "");
    const {
      tokenHeader,
      tokenHeaderString,
      tokenHeaderBase64,
    }: {
      tokenHeader: TokenHeader;
      tokenHeaderString: string;
      tokenHeaderBase64: string;
    } = AuthenticationProvider.extractTokenHeader(token);
    const { jwks_uri }: { jwks_uri: string } =
      await AuthenticationProvider.getJwksUri();
    if (jwks_uri) {
      const { keys }: { keys: OpenIdKey[] } =
        await AuthenticationProvider.getAzureJwtKeys(jwks_uri);
      if (keys?.length) {
        const matchKey: OpenIdKey = AuthenticationProvider.getMatchKey(
          keys,
          tokenHeader
        );
        if (matchKey && matchKey?.x5c?.[0]) {
          const isTokenValid = AuthenticationProvider.validateToken(
            matchKey.x5c[0],
            token
          );
          if (!isTokenValid) {
            return {
              status: 403,
              isAuthenticate: false,
              message: "User need to authenticate",
            } as AuthenticationResult;
          }
          return {
            status: 200,
            isAuthenticate: true,
            message: "Success",
          } as AuthenticationResult;
        }
        return {
          status: 500,
          isAuthenticate: false,
          message: `keys: ${JSON.stringify(keys)}, match key ${
            matchKey ? JSON.stringify(matchKey) : ""
          } tokenHeader ${JSON.stringify(
            tokenHeader
          )}, tokenHeaderString ${tokenHeaderString} tokenHeaderBase64 ${tokenHeaderBase64}`,
        } as AuthenticationResult;
      }
    }
  }
  private static getMatchKey(keys: any, tokenHeader: TokenHeader): OpenIdKey {
    return keys.find(
      (key: OpenIdKey) =>
        key.kid === tokenHeader?.kid && key.x5t === tokenHeader?.kid
    );
  }

  private static validateToken(publicKey: string, token: string): boolean {
    const key: string = `-----BEGIN CERTIFICATE-----\n${publicKey}\n-----END CERTIFICATE-----`;
    try {
      return !!verify(token, key);
    } catch (error: any) {
      return false;
    }
  }

  private static async getAzureJwtKeys(jwksUri: string): Promise<OpenIdKeys> {
    const openIdKeys: OpenIdKeys =
      await AuthenticationProvider._httpService.get<OpenIdKeys>(jwksUri);
    return openIdKeys;
  }

  private static extractTokenHeader(token: string): {
    tokenHeader: TokenHeader;
    tokenHeaderString: string;
    tokenHeaderBase64: string;
  } {
    const tokenHeaderBase64 = token.split(".")[0];
    const buf = Buffer.from(tokenHeaderBase64, "base64");
    const tokenHeaderString = buf.toString("ascii");
    const tokenHeader: TokenHeader = JSON.parse(tokenHeaderString);
    return { tokenHeader, tokenHeaderString, tokenHeaderBase64 };
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
  private static async getJwksUri(): Promise<{ jwks_uri: string }> {
    return await AuthenticationProvider._httpService.get<OpenIdConfig>(
      "https://login.microsoftonline.com/common/.well-known/openid-configuration"
    );
  }
}
