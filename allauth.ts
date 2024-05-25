import axios, { AxiosInstance, AxiosResponse } from "axios";

type Client = "app" | "browser";

interface ConfigurationResponse {
  status: number;
  data: {
    account: {
      authentication_method: "email" | "username" | "username_email";
    };
    socialaccount: {
      providers: Provider[];
    };
    mfa: {
      supported_types: AuthenticatorType[];
    };
    usersessions: {
      track_activity: boolean;
    };
  };
}

interface Provider {
  id: string;
  name: string;
  client_id?: string;
  flows: ("provider_redirect" | "provider_token")[];
}

type AuthenticatorType = "recovery_codes" | "totp";

interface AuthenticationResponse {
  status: number;
  data: {
    flows: Flow[];
  };
  meta: {
    is_authenticated: boolean;
    session_token?: string;
    access_token?: string;
  };
}

interface Flow {
  id:
    | "verify_email"
    | "login"
    | "signup"
    | "provider_redirect"
    | "provider_signup"
    | "provider_token"
    | "mfa_authenticate"
    | "reauthenticate"
    | "mfa_reauthenticate";
  provider?: Provider;
  is_pending?: boolean;
}

interface AuthenticatedResponse {
  status: number;
  data: {
    user: User;
    methods: AuthenticationMethod[];
  };
  meta: {
    is_authenticated: true;
    session_token?: string;
    access_token?: string;
  };
}

export interface User {
  id: number | string;
  display: string;
  has_usable_password: boolean;
  email: string;
  username?: string;
}

type AuthenticationMethod =
  | {
      method: "password";
      at: number;
      email?: string;
      username?: string;
    }
  | {
      method: "password";
      at: number;
      reauthenticated: true;
    }
  | {
      method: "socialaccount";
      at: number;
      provider: string;
      uid: string;
    }
  | {
      method: "mfa";
      at: number;
      type: AuthenticatorType;
      reauthenticated?: boolean;
    };

interface ErrorResponse {
  status: number;
  errors: {
    code: string;
    param?: string;
    message: string;
  }[];
}

interface EmailVerificationInfoResponse {
  status: number;
  data: {
    email: string;
    user: User;
  };
  meta: {
    is_authenticating: boolean;
  };
}

interface PasswordResetInfoResponse {
  status: number;
  data: {
    user: User;
  };
}

interface EmailAddress {
  email: string;
  primary: boolean;
  verified: boolean;
}

interface ProviderAccount {
  uid: string;
  display: string;
  provider: Provider;
}

interface TOTPAuthenticator {
  type: "totp";
  last_used_at: number | null;
  created_at: number;
}

interface RecoveryCodesAuthenticator {
  type: "recovery_codes";
  last_used_at: number | null;
  created_at: number;
  total_code_count: number;
  unused_code_count: number;
}

interface SensitiveRecoveryCodesAuthenticator
  extends RecoveryCodesAuthenticator {
  unused_codes: string[];
}

interface Session {
  user_agent: string;
  ip: string;
  created_at: number;
  is_current: boolean;
  id: number;
  last_seen_at?: number;
}

export class AllauthClient {
  private axiosInstance: AxiosInstance;

  constructor(private client: Client, private apiBaseUrl: string) {
    this.axiosInstance = axios.create({
      baseURL: `${apiBaseUrl}/_allauth/${client}/v1`,
    });
  }

  async getConfiguration(): Promise<ConfigurationResponse> {
    const response: AxiosResponse<ConfigurationResponse> =
      await this.axiosInstance.get("/config");
    return response.data;
  }

  async login(data: {
    username?: string;
    email?: string;
    password: string;
  }): Promise<AuthenticatedResponse> {
    const response: AxiosResponse<AuthenticatedResponse> =
      await this.axiosInstance.post("/auth/login", data);
    return response.data;
  }

  async signup(data: {
    email?: string;
    username?: string;
    password: string;
  }): Promise<AuthenticatedResponse> {
    const response: AxiosResponse<AuthenticatedResponse> =
      await this.axiosInstance.post("/auth/signup", data);
    return response.data;
  }

  async getEmailVerificationInfo(
    key: string
  ): Promise<EmailVerificationInfoResponse> {
    const response: AxiosResponse<EmailVerificationInfoResponse> =
      await this.axiosInstance.get("/auth/email/verify", {
        headers: { "X-Email-Verification-Key": key },
      });
    return response.data;
  }

  async verifyEmail(
    data: { key: string },
    sessionToken?: string
  ): Promise<AuthenticatedResponse> {
    let config = {
      headers: {},
    };

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      config.headers["X-Session-Token"] = sessionToken;
    }

    const response: AxiosResponse<AuthenticatedResponse> =
      await this.axiosInstance.post(`/auth/email/verify`, data, config);
    return response.data;
  }

  async reauthenticate(
    data: { password: string },
    sessionToken?: string
  ): Promise<AuthenticatedResponse> {
    let config = {
      headers: {},
    };

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      config.headers["X-Session-Token"] = sessionToken;
    }

    const response: AxiosResponse<AuthenticatedResponse> =
      await this.axiosInstance.post("/auth/reauthenticate", data, config);
    return response.data;
  }

  async requestPassword(data: { email: string }): Promise<void> {
    await this.axiosInstance.post("/auth/password/request", data);
  }

  async getPasswordResetInfo(key: string): Promise<PasswordResetInfoResponse> {
    const response: AxiosResponse<PasswordResetInfoResponse> =
      await this.axiosInstance.get("/auth/password/reset", {
        headers: { "X-Password-Reset-Key": key },
      });
    return response.data;
  }

  async resetPassword(data: {
    key: string;
    password: string;
  }): Promise<AuthenticatedResponse> {
    const response: AxiosResponse<AuthenticatedResponse> =
      await this.axiosInstance.post("/auth/password/reset", data);
    return response.data;
  }

  async providerToken(
    data: {
      provider: string;
      process: "login" | "connect";
      token: { client_id: string; id_token?: string; access_token?: string };
    },
    sessionToken?: string
  ): Promise<AuthenticatedResponse> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    const response: AxiosResponse<AuthenticatedResponse> =
      await this.axiosInstance.post("/auth/provider/token", data, { headers });
    return response.data;
  }

  async providerSignup(data: {
    email: string;
  }): Promise<AuthenticatedResponse> {
    const response: AxiosResponse<AuthenticatedResponse> =
      await this.axiosInstance.post("/auth/provider/signup", data);
    return response.data;
  }

  async mfaAuthenticate(
    data: { code: string },
    sessionToken?: string
  ): Promise<AuthenticatedResponse> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    const response: AxiosResponse<AuthenticatedResponse> =
      await this.axiosInstance.post("/auth/2fa/authenticate", data, {
        headers,
      });
    return response.data;
  }

  async mfaReauthenticate(
    sessionToken?: string
  ): Promise<AuthenticatedResponse> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    const response: AxiosResponse<AuthenticatedResponse> =
      await this.axiosInstance.post("/auth/2fa/reauthenticate", null, {
        headers,
      });
    return response.data;
  }

  async requestLoginCode(data: { email: string }): Promise<void> {
    await this.axiosInstance.post("/auth/code/request", data);
  }

  async confirmLoginCode(data: {
    code: string;
  }): Promise<AuthenticatedResponse> {
    const response: AxiosResponse<AuthenticatedResponse> =
      await this.axiosInstance.post("/auth/code/confirm", data);
    return response.data;
  }

  async getProviderAccounts(sessionToken?: string): Promise<ProviderAccount[]> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    const response: AxiosResponse<{ status: number; data: ProviderAccount[] }> =
      await this.axiosInstance.get("/account/providers", { headers });
    return response.data.data;
  }

  async disconnectProviderAccount(
    data: { provider: string; account: string },
    sessionToken?: string
  ): Promise<ProviderAccount[]> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    const response: AxiosResponse<{ status: number; data: ProviderAccount[] }> =
      await this.axiosInstance.delete("/account/providers", { headers, data });
    return response.data.data;
  }

  async getEmailAddresses(sessionToken?: string): Promise<EmailAddress[]> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    const response: AxiosResponse<{ status: number; data: EmailAddress[] }> =
      await this.axiosInstance.get("/account/email", { headers });
    return response.data.data;
  }

  async addEmailAddress(
    data: { email: string },
    sessionToken?: string
  ): Promise<EmailAddress[]> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    const response: AxiosResponse<{ status: number; data: EmailAddress[] }> =
      await this.axiosInstance.post("/account/email", data, { headers });
    return response.data.data;
  }

  async requestEmailVerification(
    data: { email: string },
    sessionToken?: string
  ): Promise<void> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    await this.axiosInstance.put("/account/email", data, { headers });
  }

  async changePrimaryEmailAddress(
    data: { email: string; primary: true },
    sessionToken?: string
  ): Promise<EmailAddress[]> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    const response: AxiosResponse<{ status: number; data: EmailAddress[] }> =
      await this.axiosInstance.patch("/account/email", data, { headers });
    return response.data.data;
  }

  async removeEmailAddress(
    data: { email: string },
    sessionToken?: string
  ): Promise<EmailAddress[]> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    const response: AxiosResponse<{ status: number; data: EmailAddress[] }> =
      await this.axiosInstance.delete("/account/email", { headers, data });
    return response.data.data;
  }

  async getAuthenticators(
    sessionToken?: string
  ): Promise<(TOTPAuthenticator | RecoveryCodesAuthenticator)[]> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    const response: AxiosResponse<{
      status: number;
      data: (TOTPAuthenticator | RecoveryCodesAuthenticator)[];
    }> = await this.axiosInstance.get("/account/authenticators", { headers });
    return response.data.data;
  }

  async getTOTPAuthenticator(
    sessionToken?: string
  ): Promise<TOTPAuthenticator> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    const response: AxiosResponse<{ status: number; data: TOTPAuthenticator }> =
      await this.axiosInstance.get("/account/authenticators/totp", { headers });
    return response.data.data;
  }

  async activateTOTP(
    data: { code: string },
    sessionToken?: string
  ): Promise<TOTPAuthenticator> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    const response: AxiosResponse<{ status: number; data: TOTPAuthenticator }> =
      await this.axiosInstance.post("/account/authenticators/totp", data, {
        headers,
      });
    return response.data.data;
  }

  async deactivateTOTP(sessionToken?: string): Promise<void> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    await this.axiosInstance.delete("/account/authenticators/totp", {
      headers,
    });
  }

  async getRecoveryCodes(
    sessionToken?: string
  ): Promise<SensitiveRecoveryCodesAuthenticator> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    const response: AxiosResponse<{
      status: number;
      data: SensitiveRecoveryCodesAuthenticator;
    }> = await this.axiosInstance.get(
      "/account/authenticators/recovery_codes",
      { headers }
    );
    return response.data.data;
  }

  async regenerateRecoveryCodes(sessionToken?: string): Promise<void> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    await this.axiosInstance.post(
      "/account/authenticators/recovery_codes",
      null,
      { headers }
    );
  }

  async getAuthenticationStatus(
    sessionToken?: string
  ): Promise<AuthenticatedResponse | AuthenticationResponse> {
    const headers: Record<string, string> = {};
    if (sessionToken) {
      headers["X-Session-Token"] = sessionToken;
    }
    const response: AxiosResponse<
      AuthenticatedResponse | AuthenticationResponse
    > = await this.axiosInstance.get("/auth/session", { headers });
    return response.data;
  }

  async logout(sessionToken?: string): Promise<AuthenticationResponse> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    const response: AxiosResponse<AuthenticationResponse> =
      await this.axiosInstance.delete("/auth/session", { headers });
    return response.data;
  }

  async changePassword(
    data: { current_password?: string; new_password: string },
    sessionToken?: string
  ): Promise<void> {
    const headers: Record<string, string> = {};

    if (this.client === "app") {
      if (!sessionToken) {
        throw new Error("Session token is required for app client");
      }
      headers["X-Session-Token"] = sessionToken;
    }

    await this.axiosInstance.post("/account/password/change", data, {
      headers,
    });
  }

  async getSessions(): Promise<Session[]> {
    const response: AxiosResponse<{ status: number; data: Session[] }> =
      await this.axiosInstance.get("/sessions");
    return response.data.data;
  }

  async deleteSession(): Promise<Session[]> {
    const response: AxiosResponse<{ status: number; data: Session[] }> =
      await this.axiosInstance.delete("/sessions");
    return response.data.data;
  }
}
