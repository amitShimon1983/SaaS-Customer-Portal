import { Logger } from "@azure/functions";
import {
  ActivateSubscription,
  AddSubscription,
  EditSubscriptionRequest,
  IAuthenticateResponse,
  IConfig,
  ISubscription,
} from "../../entities";
import { AuthenticationProvider, HttpProvider } from "../../utils";

export class SubscriptionApiHelper {
  public readonly _configuration: IConfig;
  public readonly _logger: Logger;
  private static _httpService: HttpProvider;
  private static _authenticationService: AuthenticationProvider;
  constructor(configuration: IConfig, log: Logger) {
    this._logger = log;
    this._configuration = configuration;
    this.initStaticMembers();
  }

  private initStaticMembers() {
    this.initHttpProvider();
    this.initAuthProvider();
  }

  private initHttpProvider() {
    if (!SubscriptionApiHelper._httpService) {
      SubscriptionApiHelper._httpService = new HttpProvider();
    }
  }

  private initAuthProvider() {
    if (!SubscriptionApiHelper._authenticationService) {
      SubscriptionApiHelper._authenticationService = new AuthenticationProvider(
        this._configuration
      );
    }
  }
  async notifyOperationState(
    subscription: ISubscription,
    editSubscription: EditSubscriptionRequest,
    updateResponse: { status: string }
  ) {
    const { access_token }: IAuthenticateResponse =
      await SubscriptionApiHelper._authenticationService.acquireAppAuthenticationToken();
    if (access_token) {
      const notifyFailureUrl = `${this._configuration.subscriptionBaseUrl}${subscription.id}/operations/${editSubscription.id}?api-version=${this._configuration.fulfillmentApiVersion}`;
      try {
        const response = await SubscriptionApiHelper._httpService.patch<any>(
          notifyFailureUrl,
          {
            headers: {
              "Content-Type": "application/json",
              Authorization: `Portal ${access_token}`,
            },
            body: JSON.stringify(updateResponse),
          }
        );
        console.log({ response });
      } catch (error: any) {
        this._logger.error(
          `[getSubscriptionDetails] error ${
            error.message
          } dateTime: ${new Date().toISOString()}`
        );
      }
    }
  }
  async getSubscriptionDetails(access_token: string, token: string) {
    this._logger.info(
      `[getSubscriptionDetails] started dateTime:${new Date().toISOString()}`
    );
    let subscription: AddSubscription;
    const resolveUrl =
      this._configuration.subscriptionBaseUrl +
      this._configuration.resolveSubscriptionEndPoint +
      this._configuration.fulfillmentApiVersion;
    try {
      subscription =
        await SubscriptionApiHelper._httpService.post<AddSubscription>(
          resolveUrl,
          {
            headers: {
              "Content-Type": "application/json",
              Authorization: `Portal ${access_token}`,
              "x-ms-marketplace-token": token,
            },
          }
        );
    } catch (error: any) {
      this._logger.error(
        `[getSubscriptionDetails] error ${
          error.message
        } dateTime: ${new Date().toISOString()}`
      );
      throw error;
    }
    this._logger.info(
      `[getSubscriptionDetails] finished dateTime:${new Date().toISOString()}`
    );
    return subscription;
  }
  async callActivateSubscriptionApi(
    subscriptionId: string,
    access_token: string,
    confirmationPayload: ActivateSubscription
  ): Promise<void> {
    const activateUrl: string =
      this._configuration.subscriptionBaseUrl +
      this._configuration.activateSubscriptionEndPoint +
      this._configuration.fulfillmentApiVersion;
    const body = JSON.stringify(confirmationPayload);
    const response = await SubscriptionApiHelper._httpService.post<{
      Message: string;
    }>(activateUrl.replace("*{subscriptionId}*", subscriptionId), {
      headers: {
        "Content-Type": "application/json",
        Authorization: `Portal ${access_token}`,
      },
      body,
    });
    if (response?.Message) {
      const errorMessage = `[callActivateSubscriptionApi] error for subscriptionId ${subscriptionId} body ${body}, api message ${response.Message}`;
      this._logger.error(errorMessage);
      throw new Error(errorMessage);
    }
  }
}
