export interface SignupRequest {
  sur_name?: string;
  last_name?: string;
  email?: string;
  phone_number?: string;
  password?: string;
  role?: "admin" | "user";
}

// Interface descript infor of verify user
export interface VerifyUserRequest {
  email?: string;
  phone_number?: string;
  code: string;
}

export interface LoginRequest {
  email?: string;
  phone_number?: string;
  password?: string;
}

export interface CognitoToken {
  accessToken: string;
  idToken: string;
  refreshToken: string;
  username?: string;
  userId?: string;
}