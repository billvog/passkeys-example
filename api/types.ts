import SimpleWebAuthnServer from "@simplewebauthn/server";

export type JwtAuthPayload = {
  username: string;
};

export type User = {
  username: string;
  registrationInfo: SimpleWebAuthnServer.VerifiedRegistrationResponse["registrationInfo"]; // used for passkeys
};
