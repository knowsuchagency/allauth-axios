# Django AllauthClient Module

This project provides an axios-based client library and higher-level react context for the excellent [Django Allauth](https://allauth.org/) library.

The `AllauthClient` module provides a client-side library for interacting with the authentication and account management endpoints of the [django-allauth openapi spec](https://docs.allauth.org/en/latest/headless/openapi-specification/). It supports both browser-based and app-based authentication flows.

## Installation

Install the `AllauthClient` module using your preferred package manager. For example, using npm:

```bash
npx jsr add @knowsuchagency/allauth-axios
```

## Usage

### Importing the AllauthClient

```typescript
import { AllauthClient } from "@knowsuchagency/allauth-axios";
```

### Creating an AllauthClient Instance

Create an instance of the `AllauthClient` by providing the client type (`'app'` or `'browser'`) and the base URL of the API:

```typescript
const allauthClient = new AllauthClient("browser", "https://api.example.com");
```

### Authentication Methods

#### Login

```typescript
const response = await allauthClient.login({
  username: "john",
  password: "secret",
});
```

#### Signup

```typescript
const response = await allauthClient.signup({
  email: "john@example.com",
  password: "secret",
});
```

#### Logout

```typescript
await allauthClient.logout(sessionToken);
```

#### Get Authentication Status

```typescript
const response = await allauthClient.getAuthenticationStatus(sessionToken);
```

### Email Verification

#### Get Email Verification Info

```typescript
const response = await allauthClient.getEmailVerificationInfo(key);
```

#### Verify Email

```typescript
const response = await allauthClient.verifyEmail({ key }, sessionToken);
```

### Password Management

#### Request Password Reset

```typescript
await allauthClient.requestPassword({ email: "john@example.com" });
```

#### Get Password Reset Info

```typescript
const response = await allauthClient.getPasswordResetInfo(key);
```

#### Reset Password

```typescript
const response = await allauthClient.resetPassword({
  key,
  password: "newPassword",
});
```

#### Change Password

```typescript
await allauthClient.changePassword(
  { current_password: "oldPassword", new_password: "newPassword" },
  sessionToken
);
```

### Social Account Management

#### Get Provider Accounts

```typescript
const providerAccounts = await allauthClient.getProviderAccounts(sessionToken);
```

#### Disconnect Provider Account

```typescript
const providerAccounts = await allauthClient.disconnectProviderAccount(
  { provider: "google", account: "john@example.com" },
  sessionToken
);
```

### Email Address Management

#### Get Email Addresses

```typescript
const emailAddresses = await allauthClient.getEmailAddresses(sessionToken);
```

#### Add Email Address

```typescript
const emailAddresses = await allauthClient.addEmailAddress(
  { email: "john@example.com" },
  sessionToken
);
```

#### Change Primary Email Address

```typescript
const emailAddresses = await allauthClient.changePrimaryEmailAddress(
  { email: "john@example.com", primary: true },
  sessionToken
);
```

#### Remove Email Address

```typescript
const emailAddresses = await allauthClient.removeEmailAddress(
  { email: "john@example.com" },
  sessionToken
);
```

### Multi-Factor Authentication (MFA)

#### Get Authenticators

```typescript
const authenticators = await allauthClient.getAuthenticators(sessionToken);
```

#### Get TOTP Authenticator

```typescript
const totpAuthenticator = await allauthClient.getTOTPAuthenticator(
  sessionToken
);
```

#### Activate TOTP

```typescript
const totpAuthenticator = await allauthClient.activateTOTP(
  { code: "123456" },
  sessionToken
);
```

#### Deactivate TOTP

```typescript
await allauthClient.deactivateTOTP(sessionToken);
```

#### Get Recovery Codes

```typescript
const recoveryCodes = await allauthClient.getRecoveryCodes(sessionToken);
```

#### Regenerate Recovery Codes

```typescript
await allauthClient.regenerateRecoveryCodes(sessionToken);
```

### Session Management

#### Get Sessions

```typescript
const sessions = await allauthClient.getSessions();
```

#### Delete Session

```typescript
const sessions = await allauthClient.deleteSession();
```

## Error Handling

The `AllauthClient` methods throw errors if there are any issues during the API requests. Make sure to handle these errors appropriately in your code.

## Configuration

The `AllauthClient` constructor accepts the following parameters:

- `client`: The client type, either `'app'` or `'browser'`.
- `apiBaseUrl`: The base URL of the API.

Make sure to provide the correct values based on your API setup.

## Conclusion

The `AllauthClient` module provides a convenient way to interact with an Allauth-compliant authentication and account management API from the client-side. It supports a wide range of authentication and account-related functionalities, making it easier to integrate authentication into your application.

Remember to handle errors appropriately and refer to the API documentation for specific endpoint details and requirements.

# React Authentication Context Module

This module provides a React context for handling user authentication using the `AllauthClient` class. It allows you to easily manage authentication state and perform authentication actions within your React components.

## Installation

```shell
npx jsr add @knowsuchagency/allauth-axios
```

## Usage

1. Wrap your application or the components that require authentication with the `AuthProvider` component. Pass the necessary props:

   - `apiBaseUrl`: The base URL of your authentication API.
   - `client`: The client type, either `'app'` or `'browser'`.

   Example:

   ```jsx
   import React from "react";
   import { AuthProvider } from "@knowsuchagency/allauth-axios/react";

   const App = () => {
     return (
       <AuthProvider apiBaseUrl="https://api.example.com" client="browser">
         {/* Your application components */}
       </AuthProvider>
     );
   };

   export default App;
   ```

2. Use the `useAuth` hook in your components to access the authentication state and functions.

   Example:

   ```jsx
   import React from "react";
   import { useAuth } from "@knowsuchagency/allauth-axios/react";

   const LoginForm = () => {
     const { login, isAuthenticated, user } = useAuth();

     const handleLogin = async (e: React.FormEvent) => {
       e.preventDefault();
       const email = "user@example.com";
       const password = "password123";
       await login({ email, password });
     };

     if (isAuthenticated) {
       return <div>Welcome, {user?.display}!</div>;
     }

     return (
       <form onSubmit={handleLogin}>
         {/* Login form fields */}
         <button type="submit">Login</button>
       </form>
     );
   };

   export default LoginForm;
   ```

## API

### AuthProvider

The `AuthProvider` component is responsible for managing the authentication state and providing the authentication context to its children components.

Props:

- `children` (required): The child components that will have access to the authentication context.
- `apiBaseUrl` (required): The base URL of your authentication API.
- `client` (required): The client type, either `'app'` or `'browser'`.

### useAuth

The `useAuth` hook allows you to access the authentication state and functions within your components.

Returns:

- `user`: The currently authenticated user object, or `null` if not authenticated.
- `isAuthenticated`: A boolean indicating whether the user is authenticated.
- `login`: A function to initiate the login process. It accepts an object with `username` (optional), `email` (optional), and `password` (required) properties.
- `signup`: A function to initiate the signup process. It accepts an object with `email` (optional), `username` (optional), and `password` (required) properties.
- `logout`: A function to log out the currently authenticated user.

## Error Handling

The module logs errors to the console if there are any issues during the authentication process. You can customize the error handling logic by modifying the `catch` blocks in the `login`, `signup`, and `logout` functions.

## Example

Here's a complete example of how to use the authentication context module in a React application:

```jsx
// App.tsx
import React from 'react';
import { AuthProvider } from "@knowsuchagency/allauth-axios/react";
import LoginForm from './LoginForm';

const App = () => {
  return (
    <AuthProvider apiBaseUrl="https://api.example.com" client="browser">
      <div>
        <h1>My App</h1>
        <LoginForm />
      </div>
    </AuthProvider>
  );
};

export default App;

// LoginForm.tsx
import React from 'react';
import { useAuth } from "@knowsuchagency/allauth-axios/react";

const LoginForm = () => {
  const { login, isAuthenticated, user, logout } = useAuth();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    const email = 'user@example.com';
    const password = 'password123';
    await login({ email, password });
  };

  const handleLogout = async () => {
    await logout();
  };

  if (isAuthenticated) {
    return (
      <div>
        <p>Welcome, {user?.display}!</p>
        <button onClick={handleLogout}>Logout</button>
      </div>
    );
  }

  return (
    <form onSubmit={handleLogin}>
      {/* Login form fields */}
      <button type="submit">Login</button>
    </form>
  );
};

export default LoginForm;
```

In this example, the `App` component wraps the application with the `AuthProvider`, passing the necessary props. The `LoginForm` component uses the `useAuth` hook to access the authentication state and functions. It renders a login form if the user is not authenticated, and a welcome message with a logout button if the user is authenticated.
