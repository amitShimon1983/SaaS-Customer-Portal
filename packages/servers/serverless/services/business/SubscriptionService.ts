import { Logger } from "@azure/functions";
import {
  IConfig,
  ISubscription,
  IAuthenticateResponse,
  IOrganization,
  IUser,
  Role,
  ActivateSubscription,
  SaasSubscriptionStatus,
  AddSubscription,
  ISubscriptionOwner,
  UpdateSubscriptionAction,
  EditSubscriptionRequest,
} from "../../entities";
import {
  BaseRepository,
  OrganizationRepositoryProvider,
  UserRepositoryProvider,
} from "../../repositories";
import {
  AuthenticationProvider,
  defaultLicense,
  defaultUserSubscription,
} from "../../utils";
import { BaseService } from "../base/BaseService";
import { SubscriptionApiHelper } from "../helpers";
import { ISubscriptionService } from "../interfaces";

export class SubscriptionService
  extends BaseService
  implements ISubscriptionService
{
  private readonly _userRepository: BaseRepository<IUser>;
  private readonly _organizationRepository: BaseRepository<IOrganization>;
  private readonly _subscriptionApiHelper: SubscriptionApiHelper;
  private static _authenticationService: AuthenticationProvider;

  constructor(config: IConfig, log: Logger) {
    super(config, log);
    this._userRepository = UserRepositoryProvider.initRepository(
      this._configuration.dbType
    );
    this._organizationRepository =
      OrganizationRepositoryProvider.initRepository(this._configuration.dbType);
    this._subscriptionApiHelper = new SubscriptionApiHelper(
      this._configuration,
      this._logger
    );
    this.initStaticMembers();
  }

  private initAuthProvider() {
    if (!SubscriptionService._authenticationService) {
      SubscriptionService._authenticationService = new AuthenticationProvider(
        this._configuration
      );
    }
  }

  private initStaticMembers() {
    this.initAuthProvider();
  }

  async getValidSubscription(tenantId: string): Promise<ISubscription> {
    let validSubscription: ISubscription;
    const logMessage = `tenantId ${tenantId}, dateTime ${new Date().toISOString()}`;
    this._logger.info(
      `[SubscriptionService - getValidSubscription] start for ${logMessage}`
    );
    const validSubscriptions = await this.getValidSubscriptions(tenantId);
    for (let index = 0; index < validSubscriptions?.length; index++) {
      const subscription: ISubscription = validSubscriptions[index];
      const assignedLicensesCount = await this.getAssignedLicenseCount(
        subscription.id
      );
      if (assignedLicensesCount < subscription.quantity) {
        this._logger.info(
          `[SubscriptionService - getValidSubscription] found subscription for ${logMessage}, subscriptionId ${subscription.id}`
        );
        validSubscription = subscription;
        break;
      }
    }
    this._logger.info(
      `[SubscriptionService - getValidSubscription] finish for ${logMessage}`
    );
    return validSubscription;
  }

  async getAssignedLicenseCount(subscriptionId: string): Promise<number> {
    const response: IUser[] = await this._userRepository.find<IUser>({
      subscriptionId: subscriptionId,
    });
    return response?.length || 0;
  }

  async getValidSubscriptions(tenantId: string): Promise<ISubscription[]> {
    const organization =
      await this._organizationRepository.findOne<IOrganization>({
        tenantId,
      });
    const validSubscription =
      organization?.subscriptions?.filter(
        (subscription: ISubscription) =>
          subscription.saasSubscriptionStatus ===
          SaasSubscriptionStatus.Subscribed
      ) || [];
    return validSubscription;
  }

  async updateSubscriptionState(
    action: UpdateSubscriptionAction,
    editSubscription: EditSubscriptionRequest
  ): Promise<void> {
    await this["subscription" + action](editSubscription);
  }

  async subscriptionReinstate(
    editSubscription: EditSubscriptionRequest
  ): Promise<void> {
    const { subscription } = editSubscription;
    const { id, purchaser } = subscription;
    const { tenantId } = purchaser;
    const logMessage = `subscriptionId ${id} tenantId ${tenantId} change status to ${SaasSubscriptionStatus.Suspended}`;
    this._logger.info(
      `[SubscriptionService - reinstateSubscription] start at ${new Date().toISOString()} for ${logMessage}`
    );
    try {
      this.updateSubscriptionStatus(
        tenantId,
        subscription,
        SaasSubscriptionStatus.Subscribed
      );
    } catch (error: any) {
      this._logger.info(
        `[SubscriptionService - reinstateSubscription] error at ${new Date().toISOString()} for ${logMessage}, error ${
          error.message
        }`
      );
      throw error;
    }
    this._logger.info(
      `[SubscriptionService - reinstateSubscription] finish at ${new Date().toISOString()} for ${logMessage}`
    );
  }

  async subscriptionSuspend(
    editSubscription: EditSubscriptionRequest
  ): Promise<void> {
    const { subscription } = editSubscription;
    const { id, purchaser } = subscription;
    const { tenantId } = purchaser;
    const logMessage = `subscriptionId ${id} tenantId ${tenantId} change status to ${SaasSubscriptionStatus.Suspended}`;
    this._logger.info(
      `[SubscriptionService - suspendSubscription] start at ${new Date().toISOString()} for ${logMessage}`
    );
    try {
      this.updateSubscriptionStatus(
        tenantId,
        subscription,
        SaasSubscriptionStatus.Suspended
      );
    } catch (error: any) {
      this._logger.info(
        `[SubscriptionService - suspendSubscription] error at ${new Date().toISOString()} for ${logMessage}, error ${
          error.message
        }`
      );
      throw error;
    }
    this._logger.info(
      `[SubscriptionService - suspendSubscription] finish at ${new Date().toISOString()} for ${logMessage}`
    );
  }

  async subscriptionChangePlan(
    editSubscription: EditSubscriptionRequest
  ): Promise<void> {
    const { subscriptionId, planId, subscription } = editSubscription;
    const logMessage = `subscriptionId ${subscriptionId}, from planId ${subscription?.planId} to planId ${planId}, tenantId ${subscription?.purchaser?.tenantId}`;
    this._logger.info(
      `[SubscriptionService - changeSubscriptionPlan] start at ${new Date().toISOString()} for ${logMessage}`
    );
    const newSubscription: ISubscription = {
      ...subscription,
      planId,
    };
    try {
      await this.updateSubscription(newSubscription);
    } catch (error) {
      this._logger.error(
        `[SubscriptionService - changeSubscriptionPlan] error at ${new Date().toISOString()} for ${logMessage}, error ${
          error.message
        }`
      );
      throw error;
    }
    this._logger.info(
      `[SubscriptionService - changeSubscriptionPlan] finish at ${new Date().toISOString()} for ${logMessage}`
    );
  }

  async subscriptionChangeQuantity(
    editSubscription: EditSubscriptionRequest
  ): Promise<void> {
    const { subscriptionId, quantity, subscription } = editSubscription;
    const logMessage = `subscriptionId ${subscriptionId}, from quantity ${subscription?.quantity} to quantity ${quantity}, tenantId ${subscription?.purchaser?.tenantId}`;
    this._logger.info(
      `[SubscriptionService - changeSubscriptionQuantity] start at ${new Date().toISOString()} for ${logMessage}`
    );
    const newSubscription: ISubscription = {
      ...subscription,
      quantity: quantity,
    };
    let isValid = true;
    if (quantity < subscription.quantity) {
      isValid = await this.verifyIfCanUpdateSubscription(
        subscription.id,
        quantity
      );
    }
    if (!isValid) {
      // if smaller then quantity ok else call microsoft api with failed status.
      const updateResponse = { status: "Failure" };
      await this._subscriptionApiHelper.notifyOperationState(
        subscription,
        editSubscription,
        updateResponse
      );
    } else {
      await this.updateSubscription(newSubscription);
    }

    this._logger.info(
      `[SubscriptionService - changeSubscriptionQuantity] finish at ${new Date().toISOString()} for ${logMessage}`
    );
  }

  private async verifyIfCanUpdateSubscription(
    subscriptionId: string,
    quantity: number
  ) {
    const assignedLicensesCount = await this.getAssignedLicenseCount(
      subscriptionId
    );
    return assignedLicensesCount < quantity;
  }

  private async updateSubscription(newSubscription: ISubscription) {
    const { id } = newSubscription;
    const logMessage = `subscriptionId ${id}, tenantId ${newSubscription?.purchaser?.tenantId}`;
    this._logger.info(
      `[SubscriptionService - changeSubscriptionQuantity] start at ${new Date().toISOString()} for ${logMessage}`
    );
    try {
      const organization: IOrganization =
        await this.getOrganizationWithFilteredUpdatedSubscription(
          newSubscription
        );
      if (organization) {
        await this.updateOrganizationSubscriptions(
          organization,
          newSubscription
        );
      }
    } catch (error: any) {
      this._logger.error(
        `[SubscriptionService - changeSubscriptionQuantity] error at ${new Date().toISOString()} for ${logMessage}, error ${
          error.message
        }`
      );
      throw error;
    }
    this._logger.info(
      `[SubscriptionService - changeSubscriptionQuantity] finish at ${new Date().toISOString()} for ${logMessage}`
    );
  }

  async subscriptionUnsubscribe(
    editSubscription: EditSubscriptionRequest
  ): Promise<void> {
    const { subscription } = editSubscription;
    const { id, quantity, purchaser, offerId } = subscription;
    const { tenantId } = purchaser;
    const logMessage = `subscriptionId ${id}, tenantId ${
      purchaser.tenantId
    } offerId ${offerId} quantity ${quantity}, userId ${
      purchaser.objectId
    }, dateTime ${new Date().toISOString()}`;
    this._logger.info(
      `[SubscriptionService - removeSubscription] start for ${logMessage}`
    );

    await this.createOrUpdateSubscriptionOwners(subscription);
    await this.removeAllSubscriptionUsers(tenantId, id);
    await this.updateSubscriptionStatus(
      tenantId,
      subscription,
      SaasSubscriptionStatus.Unsubscribed
    );
    this._logger.info(
      `[SubscriptionService - removeSubscription] finish for ${logMessage}`
    );
  }

  private async updateSubscriptionStatus(
    tenantId: string,
    subscription: ISubscription,
    newStatus: SaasSubscriptionStatus
  ) {
    const logMessage = `tenantId ${tenantId}, subscriptionId ${
      subscription.id
    }, dateTime ${new Date().toISOString()}`;
    this._logger.info(
      `[SubscriptionService - removeSubscription] start for ${logMessage}`
    );
    try {
      const organization =
        await this._organizationRepository.findOne<IOrganization>({ tenantId });
      const dbSubscription: ISubscription = this.getOrganizationSubscription(
        organization,
        subscription
      );
      dbSubscription.saasSubscriptionStatus = newStatus;
      organization.subscriptions = organization.subscriptions.filter(
        (s: ISubscription) => s.id !== dbSubscription.id
      );
      await this.updateOrganizationSubscriptions(organization, dbSubscription);
    } catch (error: any) {
      this._logger.error(
        `[SubscriptionService - removeSubscription] error for ${logMessage}, error: ${error.message}`
      );
      throw error;
    }

    this._logger.info(
      `[SubscriptionService - removeSubscription] finish for ${logMessage}`
    );
  }

  private async removeAllSubscriptionUsers(
    tenantId: string,
    subscriptionId: string
  ) {
    const logMessage = `for tenant Id ${tenantId}, subscriptionId ${subscriptionId}, dateTime ${new Date().toISOString()}`;
    this._logger.info(
      `[SubscriptionService - removeAllSubscriptionUsers] start for ${logMessage}`
    );

    try {
      const users: IUser[] = await this._userRepository.find<IUser>({
        tenantId,
        subscriptionId,
      });
      for (let index = 0; index < users?.length; index++) {
        const user = users[index];
        await this._userRepository.findOneAndUpdate(
          { _id: user._id },
          defaultUserSubscription
        );
        this._logger.info(
          `[SubscriptionService - removeAllSubscriptionUsers] remove subscription from user ${user._id}, ${logMessage}`
        );
      }
    } catch (error: any) {
      this._logger.error(
        `[SubscriptionService - removeAllSubscriptionUsers] error for ${logMessage}, error: ${error.message}`
      );
      throw error;
    }
    this._logger.info(
      `[SubscriptionService - removeAllSubscriptionUsers] finish for ${logMessage}`
    );
  }

  async resolveSubscription(token: string): Promise<ISubscription> {
    this._logger.info(
      `[resolveSubscription] started ${new Date().toISOString()}`
    );
    let subscriptionRes: AddSubscription;
    try {
      const { access_token }: IAuthenticateResponse =
        await SubscriptionService._authenticationService.acquireAppAuthenticationToken();
      if (access_token) {
        subscriptionRes =
          await this._subscriptionApiHelper.getSubscriptionDetails(
            access_token,
            token
          );
        await this.activateSubscription(
          subscriptionRes.subscription,
          access_token
        );
        if (subscriptionRes?.subscription) {
          const organization: IOrganization =
            await this.getOrganizationWithFilteredUpdatedSubscription(
              subscriptionRes.subscription
            );
          await this.updateOrganizationSubscriptions(
            organization,
            subscriptionRes.subscription
          );
          await this.createOrUpdateSubscriptionOwners(
            subscriptionRes.subscription
          );
        }
      }
    } catch (error: any) {
      this._logger.error(
        `[resolveSubscription] error: ${
          error.message
        } ${new Date().toISOString()}`
      );
      throw error;
    }
    this._logger.info(
      `[resolveSubscription] finished ${new Date().toISOString()}`
    );
    return subscriptionRes?.subscription;
  }

  private async getOrganizationWithFilteredUpdatedSubscription(
    subscription: ISubscription
  ) {
    const organization: IOrganization = await this.getOrCreateOrganization(
      subscription
    );
    const dbSubscription = this.getOrganizationSubscription(
      organization,
      subscription
    );
    if (dbSubscription) {
      organization.subscriptions = organization.subscriptions.filter(
        (s: ISubscription) => s.id !== dbSubscription.id
      );
    }
    return organization;
  }

  async activateSubscription(
    subscriptionRes: ISubscription,
    access_token: string
  ): Promise<void> {
    const isSubscriptionActive =
      subscriptionRes.saasSubscriptionStatus ===
      SaasSubscriptionStatus.Subscribed;
    if (!isSubscriptionActive) {
      const activatePayload: ActivateSubscription = {
        planId: subscriptionRes.planId,
        quantity: subscriptionRes.quantity,
      };
      await this._subscriptionApiHelper.callActivateSubscriptionApi(
        subscriptionRes.id,
        access_token,
        activatePayload
      );
      subscriptionRes.saasSubscriptionStatus =
        SaasSubscriptionStatus.Subscribed;
    }
  }

  private getOrganizationSubscription(
    organization: IOrganization,
    subscriptionRes: ISubscription
  ): ISubscription {
    let dbSubscription;
    const message = `tenantId ${organization.tenantId}, purchaser objectId ${
      subscriptionRes.purchaser.objectId
    } beneficiary objectId ${
      subscriptionRes.beneficiary.objectId
    } dateTime ${new Date().toISOString()}`;
    this._logger.info(
      `[SubscriptionService - isSubScriptionAlreadyAdded] start for ${message}`
    );
    try {
      dbSubscription = organization?.subscriptions?.find(
        (subscription: ISubscription) => subscription.id === subscriptionRes.id
      );
    } catch (error: any) {
      this._logger.error(
        `[SubscriptionService - isSubScriptionAlreadyAdded] error for ${message}, error: ${error.message}`
      );
      throw error;
    }
    this._logger.info(
      `[SubscriptionService - isSubScriptionAlreadyAdded] found subscription for subscription Id ${subscriptionRes.id}, ${message}`
    );
    return dbSubscription;
  }

  private async updateOrganizationSubscriptions(
    organization: IOrganization,
    subscriptionRes: ISubscription
  ) {
    organization.subscriptions = organization?.subscriptions
      ? [...organization.subscriptions, subscriptionRes]
      : [subscriptionRes];
    const updateOrganization =
      await this._organizationRepository.findOneAndUpdate(
        {
          _id: organization._id,
        },
        organization
      );
    return updateOrganization;
  }

  private async getOrCreateOrganization(
    subscriptionRes: ISubscription
  ): Promise<IOrganization> {
    return await this._organizationRepository.findOneAndUpdate<IOrganization>(
      {
        tenantId: subscriptionRes?.purchaser.tenantId,
      },
      { tenantId: subscriptionRes?.purchaser.tenantId }
    );
  }

  private async createOrUpdateSubscriptionOwners(subscription: ISubscription) {
    const { purchaser, beneficiary, id } = subscription;
    let users: IUser[];
    const logMessage = `subscriptionId ${id} tenantId ${purchaser.tenantId}, purchaser emailId ${purchaser.emailId} beneficiary emailId ${beneficiary.emailId}`;
    this._logger.info(
      `[createOrUpdateSubscriptionOwners] start for  ${logMessage}`
    );
    try {
      const isPurchaserIsBeneficiary = this.isPurchaserIsBeneficiary(
        purchaser,
        beneficiary
      );

      const usersQueries = this.prepareFindOwnerQuery(
        isPurchaserIsBeneficiary,
        subscription
      );
      users = await this.findOwnerOrCreateUser(usersQueries, subscription);
    } catch (error: any) {
      this._logger.error(
        `[createOrUpdateSubscriptionOwners] error for ${logMessage}, error message ${error.message}`
      );
      throw error;
    }
    this._logger.info(
      `[createOrUpdateSubscriptionOwners] finish for  ${logMessage}`
    );
    return users;
  }

  private isPurchaserIsBeneficiary(
    purchaser: ISubscriptionOwner,
    beneficiary: ISubscriptionOwner
  ) {
    return purchaser.objectId === beneficiary?.objectId;
  }

  private prepareFindOwnerQuery(
    isPurchaserIsBeneficiary: boolean,
    subscription: ISubscription
  ) {
    const query = [
      {
        userId: subscription?.purchaser.objectId,
        tenantId: subscription?.purchaser.tenantId,
        upn: subscription?.purchaser.emailId,
      },
    ];
    if (!isPurchaserIsBeneficiary) {
      query.push({
        tenantId: subscription?.beneficiary.tenantId,
        userId: subscription?.beneficiary?.objectId,
        upn: subscription?.beneficiary?.emailId,
      });
    }
    return query;
  }

  private async findOwnerOrCreateUser(
    usersQueries: { userId: string; tenantId: string; upn: string }[],
    subscription: ISubscription
  ) {
    const isSubscribe =
      subscription.saasSubscriptionStatus === SaasSubscriptionStatus.Subscribed;
    const owners: IUser[] = [];
    for (let index = 0; index < usersQueries?.length; index++) {
      const userQuery = usersQueries[index];
      const userData: IUser = {
        ...userQuery,
        role: isSubscribe ? Role.Admin : Role.Member,
        license: defaultLicense,
      };
      const owner: IUser = await this._userRepository.findOneAndUpdate(
        userQuery,
        userData
      );
      if (owner) {
        owners.push(owner);
      }
    }
    return owners;
  }
}
