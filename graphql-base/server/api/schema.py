# server/api/schema.py
type_defs = """
schema {
  query: Query
  mutation: Mutation
}

type Query {
  health: String!
  me: User
  ping: String!
  authSession: AuthSession
}

type User {
  sub: String
  role: String
  scope: String
  email: String
}

# keep AuthTokens for simple token-only responses if needed
type AuthTokens {
  accessToken: String!
  refreshToken: String!
}

# New richer session type returned by login
type AuthSession {
  accessToken: String!
  refreshToken: String
  tokenType: String!
  issuedAt: Int
  expiresAt: Int
  expiresIn: Int
  scope: String
  role: String
  userId: String
  chainId: String
}

type Mutation {
  # login now returns the richer AuthSession
  login(username: String!, password: String!): AuthSession!

  # keep token lifecycle mutations
  refreshToken(token: String!): AuthTokens!
  logout(token: String!): Boolean!
  revokeToken(token: String!): Boolean!
  revokeRotationChain(startJti: String!): Boolean!
  adminOnly: String
  introspectToken(token: String!): String

  adminRotateKey(newKid: String!, newKeyMaterial: String!, makePreferred: Boolean = true): Boolean!
  retireKid(kid: String!): Boolean!
}
"""
