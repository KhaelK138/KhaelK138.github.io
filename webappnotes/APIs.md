---
layout: blank
pagetitle: API Testing
---


**Recon**
- Always start with API recon if documentation isn't provided
- If documentation is available, review for endpoint resources
- Always attempt to view base paths of resources (/users/ for /users/1/)

**Modifying HTTP Methods**
- Always attempt dangerous HTTP methods on resource (DELETE, PATCH), even if not specified in the documentation

**Modifying POST Data Content Types**
- Changing the `Content-Type` header of data (and properly reformatting the data, which Content type converter can do), can cause issues or bypass filters
  - E.g. JSON to XML

**Mass Assignment/Hidden Parameters**
- Including valid resource data in POST requests that isn't normally included, but is part of the resource's parameters in the database
  - For example, including price of an item when buying an item and passing JSON in the POST request (itemID: 1, price: 0)

**Server-side Parameter Pollution**
- Servers can sometimes take API requests and convert them into API requests to internal servers, so using URL characters (e.g. `&`, `#`, `=`) can cause issues
- Characters must be URL encoded since we need them as part of the parameters (and not interpreted by our browser)
- Can be used to override existing parameters, modify application data, or access unauthorized data
- Discovery: mess with existing parameters using encoded characters to see what the server does - something like `name=peter%26name=carlos` and see whose information is returned
  - PHP and other frameworks will always use the second parameter in the URL, ASP.NET combines the two, and Node.js takes the first - this logic could be used to query sensitive information
  - For example, if server converts `/users/1/` into an internal API call on an internal site with something like `/users?id=1&public=true`, we could add `%23` to our name (`#`) to cause the server to ignore `public=true`
  - Submitting something like `1%23fake` and the server still returning our user information could indicate an issue
- Additionally, this could be translated into a REST resource request (like /api/users/1/name), so using `%2f` (or `/`) can pollute these requests
- Can also inject into JSON/XML queries and such
  - E.g. `?name=peter", "access_level":"administrator` for JSON injection
- When discovering parameters, custom JS files can be a great source of parameter names to look for