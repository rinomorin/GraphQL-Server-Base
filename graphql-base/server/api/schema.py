# server/api/schema.py
"""
GraphQL SDL exported as a Python string named type_defs.
The application imports this module and expects type_defs to be available.
Edit the SDL below to add/remove types or fields.
"""

type_defs = """
schema {
  query: Query
  mutation: Mutation
}

type Query {
  health: String!
  me: User
  ping: String!
}

type User {
  sub: String
  role: String
  scope: String
  email: String
}

type AuthTokens {
  accessToken: String!
  refreshToken: String!
}

type Mutation {
  login(username: String!, password: String!): AuthTokens!
  refreshToken(token: String!): AuthTokens!
  logout(token: String!): Boolean!
  revokeToken(token: String!): Boolean!
  revokeRotationChain(startJti: String!): Boolean!
  adminOnly: String
  introspectToken(token: String!): String

  # Admin key management (requires admin privileges)
  adminRotateKey(newKid: String!, newKeyMaterial: String!, makePreferred: Boolean = true): Boolean!
  retireKid(kid: String!): Boolean!
}
"""
