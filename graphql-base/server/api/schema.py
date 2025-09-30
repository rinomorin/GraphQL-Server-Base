from ariadne import gql

type_defs = gql("""
  type Query {
    hello: String!
    books: [Book!]!
  }

  type Book {
    title: String!
    author: String!
  }
""")
