(ns io.sixtant.secrets.main
  "Tools for command line use of secrets.clj."
  (:gen-class)
  (:require [io.sixtant.secrets :as s]

            [clojure.pprint :as pprint]
            [clojure.walk :as walk]
            [clojure.java.shell :as sh]
            [clojure.string :as string]))


(defmulti command
  "The command line interface is invoked like
      $ secrets command & args"
  (fn [& args] (first args)))


(def commands {})


(defmacro defcommand [cmd docstring examples fnsig & body]
  `(do
     (alter-var-root
       #'commands assoc ~(str cmd)
       {:doc ~docstring :examples ~examples})
     (defmethod command ~(str cmd)
       ~fnsig
       ~@body)))


(defn get-path
  "Given all of the leftover `args`, parse out a :path parameter if any,
  otherwise use the default path for secrets."
  [args]
  (or (get (apply hash-map args) ":path") (s/secrets-path)))


(defcommand inspect
  "Inspect stored secrets in cleartext, with values replaced with '***'."
  ["inspect"
   "inspect :path my-secrets.edn"]
  [_ & args]
  (s/with-path (get-path args)
    (s/with-secrets
      (pprint/pprint
        (walk/postwalk
          (fn [x]
            ;; Replace any "leaves" (the bottom levels of the hierarchy, i.e.
            ;; the actual secrets)
            (let [is-leaf? (and (map-entry? x) (not (map? (val x))))]
              (if is-leaf?
                [(key x) "***"]
                x)))
          (s/secrets))))))


(defcommand write
  "Write the (EDN compliant) secret at some path (see also: read)."
  ["write \"[:bitso :prod]\" '{:key \"abc\" :secret \"def\"}'"
   "write \"[:bitso :prod :key]\" \"foo\" :path different-file.edn"]
  [_ path secret & args]
  (assert (string? path) "first parameter is a string path to the secret")
  (assert (string? secret) "second parameter is a secret EDN string")

  (s/with-path (get-path args)
    (s/swap-secrets! assoc-in (read-string path) (read-string secret))))


(defcommand read
  "Read the secret at the given path (see also: write)."
  ["read \"[:bitso :prod]\""
   "read \"[:bitso :prod :key]\""]
  [_ path & args]
  (assert (string? path) "first parameter is a string path to the secret")

  (s/with-path (get-path args)
    (s/with-secrets
      (pprint/pprint (apply s/secrets (read-string path))))))


(defcommand swap
  "Eval the clojure function string and use it to update the stored secrets."
  ["swap '#(assoc-in % [:bitso :prod :client-id] 123)'"
   "swap '(fn [x] (update-in x [:bitso :prod] merge {:client-id 123}))'"]
  [_ f & args]
  (let [f (eval (read-string f))]
    (s/with-path (get-path args)
      (s/swap-secrets! f))))


(defcommand eval
  "Eval the function string and print the result."
  ["eval \"(fn [secrets] (count secrets))\""
   "eval count"
   "eval '(fn [x] (clojure.string/join \newline ((juxt :key :secret) (:bitso x))))'"]
  [_ f & args]
  (let [f (eval (read-string f))]
    (s/with-path (get-path args)
      (s/with-secrets
        (println (f (s/secrets)))))))


(defcommand with-env
  "Temporarily put secrets in environmental variables and execute a command.

  Uses a map of string -> secret-path-vector, resolves each secret, and
  merges the resulting map of string -> secret into the environment variables
  before executing the command."
  ["with-env '{\"BITSO_KEY\" \"[:bitso :prod :key]\", \"BITSO_SECRET\" \"[:bitso :prod :secret]\"}' my-script.py"]
  [& args]
  (let [args (rest args)
        [path args] (if (= (first args) :path)
                      [(second args) (rest (rest args))]
                      [(s/secrets-path) args])
        [vname->path & args] args]
    (assert (string? vname->path) "first parameter is an EDN string")
    (let [vname->path (read-string vname->path)]
      (assert (map? vname->path) "first parameter is an EDN string of a map")

      (s/with-path path
        (s/with-secrets
          (let [new-env-variables
                (zipmap
                  (keys vname->path)
                  (map
                    (fn [path] (apply s/secrets (read-string path)))
                    (vals vname->path)))
                env (merge (into {} (System/getenv)) new-env-variables)
                cmd (concat args [:in *in* :env env])]
            (print (:out (apply sh/sh cmd)))
            (flush)))))))


(defn- prompt-update-password [{:keys [password] :as x}]
  (let [change? (or
                  (nil? password)
                  (do (print "Encrypt with a new password? [y/N] ")
                      (flush)
                      (= (string/lower-case (read-line)) "y")))]
    (if change?
      (let [p (s/read-password (str "Set password for " (s/secrets-path) ": "))
            p' (s/read-password "Confirm password: ")]
        (if (= p p')
          (assoc x :password p)
          (do
            (println "Passwords didn't match.")
            (recur (assoc x :password nil)))))
      x)))


(defn- edit-with-vipe [{:keys [data] :as x}]
  (let [pprinted (with-out-str (pprint/pprint data))
        {:keys [exit out err] :as data} (try
                                          (sh/sh "vipe" :in pprinted)
                                          (catch Exception e
                                            (assoc (ex-data e)
                                              :exit 1 :err (ex-message e))))]

    (when-not (= exit 0)
      (println "Failed to open decrypted keys with `vipe`!")
      (println "Try $ apt install moreutils")
      (println err)
      (throw (ex-info err data)))

    (assoc x :data (read-string out))))


(defcommand edit
  "Edit the encrypted API keys with the default text editor.

  This uses `vipe`, so it will only work on *nix systems with moreutils
  installed."
  ["edit"
   "edit :path some-other-keyfile.edn"]
  [_ & args]
  (s/with-path (get-path args)
    (-> (s/read-secrets)
        (prompt-update-password)
        (edit-with-vipe)
        (s/write-secrets))))


(defn force-width [s width]
  (let [s (->> (string/split-lines s)
               (map string/trim)
               (partition-by (comp some? seq))
               (map #(string/join " " %)))]
    (with-out-str
      (doseq [s s]
        (if-not (seq s)
          (println "")
          (loop [s s width width]
            (when (seq s)
              (let [before (subs s 0 (min width (count s)))
                    after (if (< width (count s))
                            (subs s width (inc width))
                            " ")]
                (if (= after " ")
                  (do
                    (println before)
                    (recur
                      (subs s (min (inc (count before)) (count s)) (count s))
                      width))
                  (let [words (string/split before #" ")
                        omit (last words)]
                    (println (string/join " " (butlast words)))
                    (recur
                      (string/trim
                        (subs s (max (- width (inc (count omit))) 0) (count s)))
                      width)))))))))))

(defcommand delete
  "Delete a secret at a specified path."
  ["delete \"[:some-ex :personal]\""]
  [_ path & args]
  (assert (string? path) "first parameter is a string path to the secret")

  (s/with-path (get-path args)
    (s/swap-secrets! dissoc (read-string path))))


(defcommand help
  "Show help information, either in general or for a specific command."
  ["help"
   "help eval"
   "help delete"]
  [& [_ command & _]]
  (if-let [details (get commands command)]
    (do
      (println "Command:" command)
      (println "")
      (println (force-width (:doc details) 80))
      (println "Examples:")
      (doseq [e (:examples details)]
        (println "\t" "secrets" e)))
    (do
      (println "Usage: secrets [COMMAND] [OPTION]...")
      (println "")
      (println "Usage: secrets help [COMMAND]")
      (println "")
      (println "Commands:")
      (doseq [[c {:keys [doc]}] commands]
        (println "\t" (format "%-10s %s" c (first (string/split-lines doc)))))
      (println "")
      (println "All commands accept a :path <secrets-file> option at the end,")
      (println "except with-env, which expects :path at the start.\n")
      (println "Examples:")
      (println "\tsecrets" (get-in commands ["write" :examples 0]))
      (println "\tsecrets" (get-in commands ["write" :examples 1]))
      (println "\tsecrets" (get-in commands ["read" :examples 0]))
      (println "\tsecrets" (get-in commands ["delete" :examples 0]))
      (println "\nSee: <https://github.com/SixtantIO/secrets>"))))



(defmethod command :default [& _] (command "help"))


(defn -main [& args]
  (try
    (apply command args)
    (catch Exception e
      (println "Error executing" (str (first args) ":") (ex-message e))
      (apply command "help" args)))
  (shutdown-agents)
  (System/exit 0))
