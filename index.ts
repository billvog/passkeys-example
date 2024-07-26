require("dotenv").config();

import * as SimpleWebAuthnServer from "@simplewebauthn/server";
import base64url from "base64url";
import bodyParser from "body-parser";
import cors from "cors";
import express from "express";
import { convertChallenge, getNewChallenge } from "./helpers";
import path from "path";

// Create and configure the express app
const app = express();

app.use(cors({ origin: "*" }));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

let users: {
  [
    key: string
  ]: SimpleWebAuthnServer.VerifiedRegistrationResponse["registrationInfo"];
} = {};
let challenges: { [key: string]: string } = {};

const rpId = "localhost";
const expectedOrigin = ["http://localhost:3000"];

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Server started on port", PORT);
});

app.use(express.static(path.join(__dirname, "client/dist")));

app.post("/register/start", (req, res) => {
  let username = req.body.username as string;
  let challenge = getNewChallenge();
  challenges[username] = convertChallenge(challenge);

  res.json({
    challenge,
    rp: {
      id: rpId,
      name: "webauthn-demo",
    },
    user: {
      id: base64url.encode(username),
      name: username,
      displayName: username,
    },
    pubKeyCredParams: [
      {
        type: "public-key",
        alg: -7,
      },
      {
        type: "public-key",
        alg: -257,
      },
    ],
    authenticatorSelection: {
      authenticatorAttachment: "cross-platform",
      userVerification: "required",
      residentKey: "preferred",
      requireResidentKey: false,
    },
  });
});

app.post("/register/finish", async (req, res) => {
  const username = req.body.username as string;

  // Verify the attestation response
  let verification;
  try {
    verification = await SimpleWebAuthnServer.verifyRegistrationResponse({
      response: req.body.data,
      expectedChallenge: challenges[username],
      expectedOrigin: expectedOrigin,
    });
  } catch (error: any) {
    console.error(error);
    return res.status(400).send({ error: error.message });
  }

  const { verified, registrationInfo } = verification;
  if (!verified) {
    return res.status(500).send({ success: false });
  }

  users[username] = registrationInfo;
  return res.status(200).send({ success: true });
});

app.post("/login/start", (req, res) => {
  let username = req.body.username as string;
  if (!users[username]) {
    return res.status(404).send({ error: "User not found" });
  }

  let challenge = getNewChallenge();
  challenges[username] = convertChallenge(challenge);

  return res.json({
    challenge,
    rpId,
    allowCredentials: [
      {
        type: "public-key",
        id: users[username].credentialID,
        transports: ["internal"],
      },
    ],
    userVerification: "preferred",
  });
});

app.post("/login/finish", async (req, res) => {
  let username = req.body.username as string;
  if (!users[username]) {
    return res.status(404).send({ error: "User not found" });
  }

  let verification;
  try {
    const user = users[username];
    verification = await SimpleWebAuthnServer.verifyAuthenticationResponse({
      expectedChallenge: challenges[username],
      response: req.body.data,
      authenticator: user,
      expectedRPID: rpId,
      expectedOrigin: expectedOrigin,
      requireUserVerification: false,
    });
  } catch (error: any) {
    console.error(error);
    return res.status(400).send({ error: error.message });
  }

  const { verified } = verification;
  if (!verified) {
    return res.status(500).send({ success: false });
  }

  return res.status(200).send({ success: true });
});
