import jwt from "jsonwebtoken";
import type { JwtAuthPayload } from "./types";

export function getNewChallenge() {
  return Math.random().toString(36).substring(2);
}

export function convertChallenge(challenge: string) {
  return btoa(challenge).replaceAll("=", "");
}

export function generateJwtToken(username: string) {
  if (typeof process.env.JWT_AUTH_SECRET !== "string") {
    throw new Error("JWT_AUTH_SECRET is not set");
  }

  return jwt.sign({ username } as JwtAuthPayload, process.env.JWT_AUTH_SECRET, {
    expiresIn: "1h",
  });
}

export function decodeJwtToken(token: string) {
  if (typeof process.env.JWT_AUTH_SECRET !== "string") {
    throw new Error("JWT_AUTH_SECRET is not set");
  }

  return jwt.verify(token, process.env.JWT_AUTH_SECRET) as JwtAuthPayload;
}
