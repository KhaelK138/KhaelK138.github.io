### GraphQL

**Finding GraphQL Endpoints**
- Universal query - `query{__typename}`
- Common endpoints:
  - `/graphql`, `/api`, `/api/graphql`, `/graphql/api`, `graphql/graphql`
  - All of the above with `v1` or `v2` in the path start/end
  - If no endpoints pop up, try using alternative HTTP methods (non-POST) with the universal query

**Exploiting Unsanitized Arguments**
- Think common web vulns here
- Example:
  - Pretend query is `query {products {id name listed}}`
  - If this returns products 1, 2, and 4, we can try to IDOR product 3 with 
    - `query {products(id: 3) {id name listed}}`

**Discovering Schema Information**
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
    - Can return lots of information, so right click the response and `Save GraphQL queries to site map` 
    - Can use online visualizers, but it didn't show a mutation query
      - http://nathanrandal.com/graphql-visualizer/ (don't use on sensitive data, run visualizer locally)
- Mutation queries
  - Will have `variables` parameter where input is specified

**Bypassing Introspection Defenses**
- Sometimes, introspection queries won't run due to being disabled
- Developers sometimes disable introspection by excluding `__schema{` keyword
  - Flawed regex can be defeated by adding spaces/new lines/comments after `__schema` (which are ignored by GraphQL)
- Introspection may sometimes only be disabled over POST, so try GET requests or POST requests with content-type of `x-www-form-urlencoded` 
  - `?query=query%7B__schema%7BqueryType%7Bname%7D%7D%7D`
  - `%0A` for a newline

**Bypassing Rate Limiting**
- Many endpoints will have a rate limiter in place, and will often be based on the number of HTTP requests received (as opposed to the number of operations performed)
  - Network level instead of application level
- This means that we can do a massive brute force of one object/query in a single request using aliases:

```
query isValidDiscount($code: Int) {
    isvalidDiscount(code:$code){
        valid
    }
    isValidDiscount2:isValidDiscount(code:$code){
        valid
    }
    isValidDiscount3:isValidDiscount(code:$code){
        valid
    }
}
```
- Python script to generate JSON-friendly aliases given a file with a list of words (brute forcing usernames example):
  - Replace `[mutations_code_here]` with `\n{mutations}\n` (Github markdown issue)

```
import json
with open("wordlist.txt") as f:
    passwords = [line.strip() for line in f]
mutations = "\n".join(
    f'bruteforce{i}: [function](input: {{[input]}}) {{ token success }}'
    for i, pw in enumerate(passwords)
)

graphql_query = {
    "query": f"mutation {{[mutations_code_here]}}"
}

print(json.dumps(graphql_query, indent=2))
```


**GraphQL CSRF**
- Arise when GraphQL endpoints don't validate content type of requests and CSRF tokens not implemented
  - POST requests with content type of `application/json` are secure as long as content type is validated
- Can use GET requests or requests with `x-www-form-urlencoded`, since they can be sent by a browser
  - Either way, need to format it in a URL encoded parameter format (with `=` and `&`)
    - Make sure that `{`, `}`, and `:` (along with other special chars) are URL encoded

