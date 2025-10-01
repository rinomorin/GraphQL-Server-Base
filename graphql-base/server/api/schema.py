from ariadne import gql

type_defs = gql("""
  type Query {
    ping: String!
    me: MeResponse
  }

  type MeResponse {
    user_id: String!
    scope: String!
    issued_at: String!
    trace_id: String!
    role: String!
  }

  type LoginResponse {
    access_token: String!
    refresh_token: String!
    token_type: String!
    expires_at: String!
    expires_in: Int!
    issued_at: String!
    user_id: String!
    scope: String!
    trace_id: String!
  }

  type Mutation {
    login(username: String!, password: String!): LoginResponse
    refreshToken(refresh_token: String!): LoginResponse
    logout: Boolean!
    revokeToken(token: String!): Boolean!
    adminOnly: String!
  }
""")
