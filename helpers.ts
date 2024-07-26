export function getNewChallenge() {
  return Math.random().toString(36).substring(2);
}

export function convertChallenge(challenge: string) {
  return btoa(challenge).replaceAll("=", "");
}
