# secrets 

For storing application secrets on disk with client-side encryption.

Uses [pbkdf2](https://en.wikipedia.org/wiki/PBKDF2) with sha512 (100,000
iterations) to convert a passphrase into a key, and encrypts the secret data
using AES256 CBC + HMAC SHA512.

Any one secrets file contains an encrypted version of a single
[EDN](https://github.com/edn-format/edn) map, with arbitrary levels of
labeled nesting.

By default, the secrets file lives at .secrets.edn in the working directory,
but this path can be changed explicitly via `with-path` (or via the `:path`
flag at the command line).


## Contents 
- [Usage from the comand line](#usage-from-the-command-line)
- [Usage from Clojure](#usage-from-clojure)

## Usage from the command line

### Install

- Download the latest release.
- Make it executable.
- Move it somewhere on your `$PATH`.

One-liner:
```
bash -c "git clone git@github.com:SixtantIO/secrets.git && cd secrets && sudo chmod 755 secrets && sudo mv secrets /usr/local/bin"
```

Alternatively, clone this repository, build the jar (`clojure -X:uberjar`),
embed the jar in an executable shell script
(`cat stub.sh secrets.jar > secrets && chmod +x secrets`), and move it onto
your path (`mv secrets /usr/local/bin/`).

Otherwise, invoke the jar directly with `java -jar secrets.jar <options>` 
instead of using `secrets <options>`.


### Editing secrets

On linux systems with `vipe` installed (from the `moreutils` package), you
can edit an encrypted file using the default system editor:

```clojure
$ secrets edit :path some-secrets.edn
```

After creating a passphrase, the editor will pop up. Write some valid EDN data:
```clojure
{:some-service-name {:prod {:key "abc" :secret "123"}}}
```

Now when you save & close, the data is encrypted to disk:

```clojure
$ secrets edit :path some-secrets.edn
Set password: 
Confirm password: 
Encrypting data for writing... Done.
Wrote 171 bytes.

$ cat some-secrets.edn
{:data "MeDQAmkXCx2kGPEJbSaL8l82wbiGpBmvFn1FgZEk8ysDoGe/A6edqQ3+0GWS+MAOxAxraaTPjdXid12sGqeITv1yQuvtzS79swoTFOGwLCYmcQHjJB6FC9zkwKbY3LjA", :iv "Yh/SVZShqynxcV7koItBWw=="}
```

### Reading & writing secrets

Write a key/secret pair for Bitso, labeled `:prod`, using the default secrets
file, and then read it back:
```clojure
$ secrets write "[:bitso :prod]" '{:key "abc" :secret "def"}'
Password: 
Encrypting data for writing... Done.
Wrote 151 bytes.

$ secrets read "[:bitso :prod]"
Password: 
{:key "abc", :secret "def"}
```

The hierarchy of the secrets file now looks like this:
```clojure
$ secrets inspect
Password: 
{:bitso {:prod {:key "***", :secret "***"}}}
```

Add another secret, maybe a personal key, and watch the hierarchy change:
```clojure
$ secrets write "[:bitso :personal]" '{:key "foo"}'
Password: 
Encrypting data for writing... Done.
Wrote 195 bytes.

$ secrets inspect
Password: 
{:bitso {:prod {:key "***", :secret "***"}, :personal {:key "***"}}}
```

You can also evaluate clojure functions against the secrets map, e.g. to list 
all of the keys nested under `:bitso`:
```clojure
$ secrets eval "#(keys (:bitso %))"
Password: 
(:prod :personal)
```


### Passing secrets to programs

Use `with-env` to retrieve stored secrets and expose them as environment 
variables to the process launched by some command. 

Quick and dirty example:
```clojure
$ secrets with-env '{"KEY" "[:bitso :prod :key]"}' python3 -c "import os; print(os.environ['KEY'])"
Password: 
abc
```

You can specify different mappings in local files, e.g.

```clojure
;; prod.env
{"API_KEY" "[:bitso :prod :key]"
 "API_SECRET" "[:bitso :prod :secret]"}
```

```python
# app.py
import os

print(os.environ["API_KEY"])
print(os.environ["API_SECRET"])
```

``` clojure
$ secrets with-env "$(cat prod.env)" python3 app.py
Password: 
abc
def
```

This way, your configuration files are specifying which keys to use without 
revealing what they are, and the contents never have to sit on disk in 
cleartext.


## Usage from Clojure

```clojure 
(in-ns 'io.sixtant.secrets)

; Use the `with-secrets` macro around any code which needs access
; (prompts for a password)
(with-secrets
  (println "Have secrets for:" (keys (secrets)))

  ; `with-secrets` is reentrant, so this second invocation doesn't prompt
  ; for anything
  (with-secrets
    (println "Bitso prod key:" (secrets :bitso :prod :key))))

; Have secrets for: (:bitso)
; Bitso prod key: abc
```
