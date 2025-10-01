# server/api/schema.py
# Centralized SDL for the GraphQL schema used by make_executable_schema

type_defs = """
scalar DateTime
scalar JSON

type TokenPair {
  access_token: String!
  refresh_token: String!
  token_type: String!
  expires_at: DateTime!
  expires_in: Int!
  issued_at: DateTime!
  user_id: String!
  scope: String!
  trace_id: String!
}

type Me {
  user_id: String!
  scope: String!
  issued_at: DateTime
  trace_id: String
  role: String
}

type Query {
  ping: String!
  me: Me
}

type Mutation {
  login(username: String!, password: String!, code_challenge: String, code_challenge_method: String): TokenPair
  refreshToken(refresh_token: String!, code_verifier: String): TokenPair
  logout: Boolean
  revokeToken(token: String!): Boolean
  revokeRotationChain(jti: String!): [String!]!
  adminOnly: String
  introspectToken(token: String!): IntrospectionResult
}

type IntrospectionResult {
  valid: Boolean!
  token_type: String
  payload: JSON
  revoked: Boolean!
  used: Boolean!
  rotated: Boolean!
  lineage: [String!]!
  issued_at: DateTime
  expires_at: DateTime
  reason: String
}
"""
