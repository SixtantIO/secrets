(ns io.sixtant.secrets
  "For storing application secrets on disk with client-side encryption.

  Uses [pbkdf2](https://en.wikipedia.org/wiki/PBKDF2) with sha512 (100,000
  iterations) to convert a passphrase into a key, and encrypts the secret data
  using AES256 CBC + HMAC SHA512.

  Any one secrets file contains an encrypted version of a single
  [EDN](https://github.com/edn-format/edn) map, with arbitrary levels of
  labeled nesting.

  The path used for the secrets file, in priority order, is one of:

  - the one explicitly specified via `with-path` (or `:path` at the command
    line),
  - the `.secrets.edn` file in the working directory, or
  - the `.secrets.edn` file in the home directory."
  (:require [buddy.core.codecs :as codecs]
            [buddy.core.nonce :as nonce]
            [buddy.core.crypto :as crypto]
            [buddy.core.kdf :as kdf]

            [clojure.java.io :as io]
            [clojure.string :as string])
  (:import (java.util Base64)
           (javax.swing JPanel JLabel JPasswordField JOptionPane)
           (clojure.lang ExceptionInfo)))


(set! *warn-on-reflection* true)


(defn default-secrets-path []
  (if (.exists (io/file ".secrets.edn"))
    ".secrets.edn"
    (let [home (System/getProperty "user.home")]
      (.getCanonicalPath (io/file home ".secrets.edn")))))


(def ^:dynamic *path* "Explicitly bound path." nil)
(defmacro with-path
  "Set the file path used for saved secrets."
  [path & body]
  `(binding [*path* ~path]
     ~@body))


(defn secrets-path
  "Location of saved secrets on disk."
  []
  (or *path* (default-secrets-path)))


;;; Primitives for key stretching & encryption


(defn bytes->b64 [^bytes b] (String. (.encode (Base64/getEncoder) b)))
(defn b64->bytes [^String s] (.decode (Base64/getDecoder) (.getBytes s)))


(defn gen-random-salt []
  "Generate a 16 byte random salt."
  (bytes->b64 (nonce/random-bytes 16)))

(defn slow-key-stretch-with-pbkdf2
  ([weak-text-key salt n-bytes]
   "Function that takes a salt parameter."
   (kdf/get-bytes
    (kdf/engine {:key weak-text-key
                 :salt (b64->bytes salt)
                 :alg :pbkdf2
                 :digest :sha512
                 :iterations 1e5}) ;; target O(100ms) on commodity hardware
    n-bytes)))



(defn encrypt
  "Modified to generate and store a random salt."
  [clear-text password]
  (let [initialization-vector (nonce/random-bytes 16)
        salt (gen-random-salt)]
    {:data (bytes->b64
            (crypto/encrypt
              (codecs/to-bytes clear-text)
              (slow-key-stretch-with-pbkdf2 password salt 64)
              initialization-vector
              {:algorithm :aes256-cbc-hmac-sha512}))
     :iv (bytes->b64 initialization-vector)
     :salt salt}))

(defn decrypt
  "Modified to check if salt is present and call the appropriate function."
  [{:keys [data iv salt]} password]
  (let [key-stretch-fn (if salt
                         #(slow-key-stretch-with-pbkdf2 % salt 64)
                         #(slow-key-stretch-with-pbkdf2 % "j3gT0zoPJos=" 64))]
    (try
      (codecs/bytes->str
       (crypto/decrypt
        (b64->bytes data)
        (key-stretch-fn password)
        (b64->bytes iv)
        {:algorithm :aes256-cbc-hmac-sha512}))
      (catch ExceptionInfo e
        (if (= (:type (ex-data e)) :validation)
          (throw (ex-info "passphrase incorrect" {}))
          (throw e))))))



(comment
  ;; Sufficiently slow to protect against brute force

  (time (encrypt "some clear text" "my password"))
  ; "Elapsed time: 245.778331 msecs"
  ;=> {:data "2jttNkz8Uk2kQ7kyRMIyPSIYZRRyAa/+ACtjP+8M4w64Bp4tE2pyVNQV299EFsSJ",
  ;    :iv "m8r6cuQICvlWjobE6sE7XQ=="}

  (time (decrypt *1 "my password"))
  ; "Elapsed time: 188.044263 msecs"
  ;=> "some clear text"
  )


;;; Passwords


(defn- try-swing-read-password
  "Prompt a password from a swing dialog box."
  [^String prompt]
  (try
    (let [panel (JPanel.)
          label (JLabel. (or prompt "Password:"))
          pass (JPasswordField. 30)]
      (.add panel label)
      (.add panel pass)
      (.requestFocus pass)
      (JOptionPane/showOptionDialog
        nil panel "Password" JOptionPane/OK_OPTION
        JOptionPane/PLAIN_MESSAGE nil
        (into-array String ["Ok"]) "Ok")
      (String. (.getPassword pass)))
    (catch Exception e
      nil)))


(defn read-password
  "Attempt to read a password via a secure console if possible, falling back
  to secure input via Swing and finally to reading via plaintext (accompanied
  by a warning)."
  ([] (read-password nil))
  ([prompt]
   (if-let [console (System/console)]
     (do
       (when prompt (print prompt) (flush))
       (String. (.readPassword console)))
     (if-let [pw (try-swing-read-password prompt)]
       pw
       (do
         (println "[WARN] No secure console available, reading via plaintext.")
         (when prompt (print prompt) (flush))
         (read-line))))))


;;; Disk (de)serialization


(defn encrypt-to-disk
  [edn-compliant-data {:keys [password path]}]
  (binding [*print-length* nil
            *print-level* nil]
    (let [f (io/file path)]
      (io/make-parents f)
      (let [encrypted (encrypt (pr-str edn-compliant-data) password)]
        (spit f (prn-str encrypted))
        encrypted))))


(defn decrypt-from-disk
  [{:keys [password path]}]
  (let [f (io/file path)]
    (if-not (.isFile f)
      {}
      (-> (slurp f) (read-string) (decrypt password) (read-string)))))


;;; Main API: read & update secrets


(def ^:dynamic *password* "See `with-password`." nil)


(defmacro with-password
  "Any calls inside `body` which would otherwise prompt for a password instead
  use the given `password`."
  [password & body]
  `(binding [*password* ~password]
     ~@body))


(def ^:dynamic *secrets* "See `with-secrets`." nil)


(defn read-secrets
  "Prefer `with-secrets`."
  []
  (let [path (secrets-path)]
    (if (.isFile (io/file path))
      (let [p (or *password* (read-password (str "Password for " path ": ")))]
        {:data (decrypt-from-disk {:password p :path path})
         :password p})
      {:data {}
       :password nil})))


(defn write-secrets
  "Prefer `swap-secrets!`."
  [{:keys [data password]}]
  (print "Encrypting data for writing...")
  (flush)
  (let [path (secrets-path)
        enc (encrypt-to-disk data {:password password :path path})]
    (println " Done.")
    (println "Wrote" (count (.getBytes (prn-str enc))) "bytes to" (str path "."))
    enc))


(defmacro with-secrets
  "Read & decrypt secrets from disk, making them available for retrieval via
  the invocation of `(secrets)` during the evaluation of `body`.

  Allows a reentrant style, i.e. if secrets are already unlocked, then they
  are NOT rebound. This is a manner of asking for the decryption key if and
  only if it has not already been given."
  [& body]
  `(binding [*secrets* (or *secrets* (:data (#'read-secrets)))]
     ~@body))


(defn secrets
  "Return the secret at `ks` with `get-in` logic, or return all secrets
  if no `ks` are provided.

  Must execute within `with-secrets`."
  [& ks]
  (if *secrets*
    (get-in *secrets* ks)
    (throw
      (IllegalStateException.
        (str "Secrets are not unlocked! Call from within " `with-secrets)))))


(defn swap-secrets!
  "Run from a REPL to update the stored keys.

  E.g. to add some new keys:

    (swap-secrets! assoc-in [:some-ex :personal] {:key :foo :secret :bar})"
  [f & args]
  (-> (read-secrets)
      (update :data #(apply f % args))
      (update :password #(or % (read-password "Password:")))
      (write-secrets)))

(defn dissoc-in
  "Dissociates an entry from a nested associative structure returning a new 
  nested structure. keys is a sequence of keys. Any empty maps that result 
  will not be present in the new structure."
  [m [k & ks]]
  (let [m' (if ks
             (if-let [submap (get m k)]
               (let [submap' (dissoc-in submap ks)]
                 (if (empty? submap')
                   (dissoc m k)
                   (assoc m k submap')))
               m)
             (dissoc m k))]
    (if (empty? m') nil m')))



(defn delete-secret!
  "Delete a secret from the secrets map. Takes a key path vector as input."
  [path]
  (swap-secrets! dissoc-in path))



(comment
  ;;; Example: accessing secrets

  (with-secrets
    (println "Have:" (keys (secrets)))
    (with-secrets ; this one is a no-op bc secrets are already unlocked
      (println "Still have:" (keys (secrets))))))


(comment
  ;;; Example: encrypting a map to send to somebody

  ;; Generate a passphrase from the unix english language word list
  (defn rng-int [n] (.nextInt (java.security.SecureRandom.) n))
  (defn rand-n [coll n] (repeatedly n #(nth coll (rng-int (count coll)))))
  (def passphrase
    (let [words (string/split-lines (slurp "/usr/share/dict/words"))]
      (string/join " " (rand-n words 5))))

  ;; Encrypt some data with the passphrase to send to somebody else
  (encrypt (prn-str {:foo :bar}) passphrase)

  ;; Then tell them they can decrypt with
  (read-string (decrypt *1 passphrase)))

(comment 
  ;; The delete-secret! function is used to remove a secret from the stored secrets. 
  ;; It requires a key sequence argument (a vector of keys) representing the nested path to the secret to be removed.

  ;; The argument `[:some-ex :personal]` means that we are targeting the secret located in the `:personal` map 
  ;; which is nested inside the `:some-ex` map in the secrets store. 

  ;; Example usage:

  (delete-secret! [:some-ex :personal])

  ;; This will remove the `:personal` secret stored under `:some-ex`. After execution, the secret will no longer exist in the storage. 

  ;; If you try to retrieve this secret after deleting it with `secrets`, you will get a nil value or an error, 
  ;; depending on whether you're trying to access the secret directly or as part of a nested structure.
  )

