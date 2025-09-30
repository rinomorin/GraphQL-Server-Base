from ariadne import QueryType

query = QueryType()

@query.field("hello")
def resolve_hello(_, info):
    return "Hello, Rino — your GraphQL backend is live!"

@query.field("books")
def resolve_books(_, info):
    return [
        {"title": "The Pragmatic Programmer", "author": "Andrew Hunt"},
        {"title": "Clean Code", "author": "Robert C. Martin"},
        {"title": "Fluent Python", "author": "Luciano Ramalho"}
    ]
