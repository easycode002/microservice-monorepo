import {
  AdminAddUserToGroupCommand,
  AdminGetUserCommand,
  CognitoIdentityProviderClient,
  ConfirmSignUpCommand,
  InitiateAuthCommand,
  InitiateAuthCommandInput,
  ListUsersCommand,
  SignUpCommand,
  SignUpCommandInput,
  UserType,
} from "@aws-sdk/client-cognito-identity-provider";
import configs from "@/src/config";
import crypto from "crypto";
// import jwtDecode from "jwt-decode";
import {
  CognitoToken,
  SignupRequest,
  VerifyUserRequest,
} from "@/src/services/types/auth-service.type";
import {
  ApplicationError,
  AUTH_MESSAGE,
  InternalServerError,
  InvalidInputError,
  LoginRequest,
  ResourceConflictError,
} from "@easycode002/ms-lib";

// Create new obj for work with aws-sdk
export const client = new CognitoIdentityProviderClient({
  region: configs.awsCognitoRegion,
  credentials: {
    accessKeyId: configs.awsAccessKeyId,
    secretAccessKey: configs.awsSecretAccessKey,
  },
});

// Class auth for handle all logic of auth
class AuthService {
  // To generate the SECRET_AUTH
  private generateSecretHash(username: string): string {
    const secret = configs.awsCognitoClientSecret;
    return crypto
      .createHmac("SHA256", secret)
      .update(username + configs.awsCognitoClientId)
      .digest("base64");
  }

  // Method for user signup
  async signup(body: SignupRequest): Promise<string> {
    // Store user infor via Email or Phone_Number
    const existingNumber = await this.getUserByEmail(
      (body.email || body.phone_number) as string
    );
    // To check existing or not
    if (existingNumber) {
      throw new ResourceConflictError(
        AUTH_MESSAGE.AUTHENTICATION.ACCOUNT_ALREADY_EXISTS
      );
    }

    // To validate User input follow via SignupRequest type
    const inputBody = {
      name: `${body.first_name} ${body.last_name}`,
      ...Object.keys(body)
        .filter((key) => key !== "first_name" && key !== "last_name")
        .reduce<Record<string, any>>((obj, key) => {
          obj[key] = body[key as keyof SignupRequest];
          return obj;
        }, {}),
    };

    // To define allow attribute to use in moment signup account
    const allowAttributes = ["email", "phone_number", "name", "custom:role"];
    // Extract specific attributes that are either allowed or related to a custom role.
    const attributes = Object.keys(inputBody)
      .filter((key) => allowAttributes.includes(key) || key == "role")
      .map((key) => ({
        Name: key === "role" ? "custom:role" : key,
        Value: inputBody[key as keyof typeof inputBody],
      }));
    // Define username
    const username = (body.email || body.password) as string;
    // Define params infor for awsCognito
    const params: SignUpCommandInput = {
      ClientId: configs.awsCognitoClientId,
      Username: username,
      Password: body.password,
      SecretHash: this.generateSecretHash(username),
      UserAttributes: attributes,
    };

    try {
      // Sign user infor via command
      const command = new SignUpCommand(params);
      const result = await client.send(command);
      return `User created successfully. Please check your ${result.CodeDeliveryDetails?.DeliveryMedium?.toLowerCase()} for a verification code.`;
    } catch (error) {
      console.log(`AuthService signup() method error: `, error);

      // To check if error
      if (error instanceof ApplicationError) {
        throw error;
      }
      // To check if account existing
      if (typeof error === "object" && error !== null && "name" in error) {
        if ((error as { name: string }).name === "UsernameExistsException") {
          throw new ResourceConflictError(
            AUTH_MESSAGE.AUTHENTICATION.ACCOUNT_ALREADY_EXISTS
          );
        }
      }
      throw new Error(`Error signing up user: ${error}`);
    }
  }

  // Method to verify user account
  async verifyUser(body: VerifyUserRequest): Promise<void> {
    // Define constant to store username(email,phone_number)
    const username = (body.email ||
      body.phone_number?.replace(/^\+/, "")) as string; // If phone_number empty return undefined, but have value return with replace to '' like pattern
    // Define params obj
    const params = {
      ClientId: configs.awsCognitoClientId,
      Username: username,
      ConfirmationCode: body.code,
      SecretHash: this.generateSecretHash(username),
    };

    try {
      const command = new ConfirmSignUpCommand(params);
      await client.send(command);
      console.log(`AuthService verifyUser() method: User verify successfully`);

      // Retrive the user to get the `role` attribute
      const userInfo = await this.getUserByUsername(username);
      const role =
        userInfo.UserAttributes?.find((attr) => attr.Name === "custom:role")
          ?.Value || "user";

      // Add the user to the group base on the `role` attribute
      await this.addToGroup(username, role);

      // Send the user info to the `User Service`
      // await axios.post(`${configs.userServiceUrl}/v1/users`, {
      //   sub: userInfo.Username,
      //   email: body.email,
      //   phone_number: body.phone_number,
      //   username: userInfo.UserAttributes?.find((attr) => attr.Name === "name")
      //     ?.Value,
      //   role,
      // });
    } catch (error) {
      console.log(`AuthService verifyUser() method error:`, error);

      // Mismatch Code
      if (typeof error === "object" && error !== null && "name" in error) {
        if ((error as { name: string }).name === "CodeMismatchException") {
          message: AUTH_MESSAGE.MFA.VERIFICATION_FAILED;
        }
      }
      throw new Error(`Error verifying user: ${error}`);
    }
  }

  // Mehtod for user login
  async login(body: LoginRequest): Promise<CognitoToken> {
    const username = (body.email || body.phone_number) as string;

    const params: InitiateAuthCommandInput = {
      AuthFlow: "USER_PASSWORD_AUTH",
      ClientId: configs.awsCognitoClientId,
      AuthParameters: {
        USERNAME: username,
        PASSWORD: body.password!,
        SECRET_HASH: this.generateSecretHash(username),
      },
    };

    try {
      const command = new InitiateAuthCommand(params);
      const result = await client.send(command);

      // Get the user info
      const congitoUsername = await this.getUserInfoFromToken(
        result.AuthenticationResult?.IdToken!
      );

      // Get the user info from the user service
      const userInfo = await axios.get(
        `${configs.userServiceUrl}/v1/users/${congitoUsername.sub}`
      );
      console.log("userInfo: ", userInfo);

      return {
        accessToken: result.AuthenticationResult?.AccessToken!,
        idToken: result.AuthenticationResult?.IdToken!,
        refreshToken: result.AuthenticationResult?.RefreshToken!,
        username: congitoUsername.sub,
        userId: userInfo.data.data._id,
      };
    } catch (error) {
      // Mismatch Password | Email or Phone Number
      if (typeof error === "object" && error !== null && "name" in error) {
        if ((error as { name: string }).name === "NotAuthorizedException") {
          throw new InvalidInputError({
            message: AUTH_MESSAGES.AUTHENTICATION.ACCOUNT_NOT_FOUND,
          });
        }
      }

      // Cognito Service Error
      if (typeof error === "object" && error !== null && "name" in error) {
        if ((error as { name: string }).name === "InternalErrorException") {
          throw new InternalServerError({
            message: AUTH_MESSAGES.ERRORS.TECHNICAL_ISSUE,
          });
        }
      }

      console.error("AuthService login() method error:", error);
      throw new Error(`Error verifying user: ${error}`);
    }
  }

  // Method to check user exist or not
  async getUserByEmail(email: string): Promise<UserType | undefined> {
    // params obj
    const params = {
      Filter: `email="${email}"`,
      UserPoolId: configs.awsCognitoIdentityPoolId,
      Limit: 1,
    };
    try {
      // Will take `params` to filter in ListUserCommand
      const listUsersCommand = new ListUsersCommand(params);
      const response = await client.send(listUsersCommand);
      console.log(`ListUsersCommand: `, response);
      // response is obj of ListUsersCommand, It return one or more list and return first user =>Users[0]
      return response.Users && response.Users[0];
    } catch (error) {
      console.log(`AuthService getUserByEmail() method error:`, error);
      throw error;
    }
  }

  // Get user via Username
  async getUserByUsername(username: string) {
    const params = {
      Username: username,
      UserPoolId: configs.awsCognitoIdentityPoolId,
    };
    try {
      const command = new AdminGetUserCommand(params);
      const userInfo = await client.send(command);
      return userInfo;
    } catch (error) {
      console.log(`AuthService getUserByEmail() method error:`, error);
      throw error;
    }
  }

  // Add user to group
  async addToGroup(username: string, groupName: string) {
    const params = {
      GroupName: groupName,
      Username: username,
      UserPoolId: configs.awsCognitoUserPoolId,
    };

    try {
      const command = new AdminAddUserToGroupCommand(params);
      await client.send(command);
      console.log(
        `AuthService verifyUser() method: User added to ${groupName} group`
      );
    } catch (error) {
      throw error;
    }
  }

  // Get user information from Token
  getUserInfoFromToken(token: string) {
    const decodedToken = jwtDecode(token);
    console.log("decodedToken: ", decodedToken);
    return decodedToken;
  }
}
export default new AuthService();
