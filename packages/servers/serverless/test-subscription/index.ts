import { AzureFunction, Context, HttpRequest } from "@azure/functions";
import { SubscriptionController, UserController } from "../controllers";
import { IAuthenticateResponse, ISubscription } from "../entities";
import { AppLoader, AuthenticationProvider, HttpProvider } from "../utils";

const httpTrigger: AzureFunction = async function (
  context: Context,
  req: HttpRequest
): Promise<void> {
  const { log } = context;
  const { appConfig } = await AppLoader.initApp(req, false);
  const userController = new UserController(appConfig, log);
  const res = await userController.getAllUsers(
    "03122737-f0d8-4f00-ae32-5ff087a3db8f"
  );
  // const httpProvider = new HttpProvider();
  // const authenticationService: AuthenticationProvider =
  //   new AuthenticationProvider(appConfig);
  // const { access_token }: IAuthenticateResponse =
  //   await authenticationService.acquireAppAuthenticationToken();
  // const res: { subscriptions: ISubscription[] } = await httpProvider.get(
  //   "https://marketplaceapi.microsoft.com/api/saas/subscriptions?api-version=2018-08-31",
  //   {
  //     headers: {
  //       "Content-Type": "application/json",
  //       Authorization: `Bearer ${access_token}`,
  //     },
  //   }
  // );

  // const subscriptionController = new SubscriptionController(appConfig, log);
  // for (let index = 0; index < res.subscriptions.length; index++) {
  //   const element = res.subscriptions[index];
  //   // if (element.saasSubscriptionStatus !== "Unsubscribed") {
  //   //   console.log("Unsubscribe");
  //   // }
  //   // if (element.saasSubscriptionStatus === "PendingFulfillmentStart") {
  //   //   await subscriptionController.activateSubscription(element, access_token);
  //   // }
  //   const subscriptionOperation = await httpProvider.get(
  //     `https://marketplaceapi.microsoft.com/api/saas/subscriptions/${element.id}/operations?api-version=2018-08-31`,
  //     {
  //       headers: {
  //         "Content-Type": "application/json",
  //         Authorization: `Bearer ${access_token}`,
  //       },
  //     }
  //   );
  //   console.log({ subscriptionOperation });
  //   const url =
  //     `https://marketplaceapi.microsoft.com/api/saas/subscriptions/${element.id}` +
  //     "?api-version=2018-08-31";
  //   const deleteRes: any = await httpProvider.delete(url, {
  //     headers: {
  //       "Content-Type": "application/json",
  //       Authorization: `Bearer ${access_token}`,
  //     },
  //   });

  //   console.log({ deleteRes });
  // }

  // if (req?.body?.action === "Unsubscribe") {
  //   await subscriptionController.unsubscribe(req?.body?.subscription);
  // }
  // // we need to create a page that calls that api and returns response to user!
  // if (req?.query?.token) {
  //   await subscriptionController.resolveSubscription(req.query.token);
  // }

  context.res = {
    status: 200,
    body: res,
  };
};

export default httpTrigger;
