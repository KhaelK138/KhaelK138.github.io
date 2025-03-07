### GraphQL

**Finding GraphQL Endpoints:**
- Universal query - `query{__typename}`
- Common endpoints:
  - `/graphql`, `/api`, `/api/graphql`, `/graphql/api`, `graphql/graphql`
  - All of the above with `v1` or `v2` in the path start/end
  - If no endpoints pop up, try using alternative HTTP methods (non-POST) with the universal query
- Suggestions
  - Apollo GraphQL will suggest amendments when errors occur, like `There is no entry for 'productInfo'. Did you mean 'productInformation' instead?`
  - These can be used to glean information about the schema
  - **Clairvoyance** uses suggestions to recover the schema
- Introspection queries
  - Built-in function that allows querying schema information
    - `query{__schema}`
    - `{"query": "{__schema{queryType{name}}}"}`
  - Description fields can sometimes have sensitive info
  - Introspection query can be sent via **{right click} > GraphQL > Set introspection query**
    - Can return lots of information, so a GraphQL visualizer online can be helpful
    - http://nathanrandal.com/graphql-visualizer/ (don't use on sensitive data, run visualizer locally)


**Exploiting Unsanitized Arguments:**
- Think common web vulns here
- Example:
  - Pretend query is `query {products {id \n name \n listed}}`
  - If this returns products 1, 2, and 4, we can try to IDOR product 3 with 
    - `query {products(id: 3) {id \n name \n listed}}`

**Discovering Schema Information:**

**Bypassing Introspection Defenses:**

**Bypassing Rate Limiting:**

**GraphQL CSRF:**
