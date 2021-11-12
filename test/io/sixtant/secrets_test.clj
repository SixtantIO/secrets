(ns io.sixtant.secrets-test
  (:require [clojure.test :refer :all]
            [clojure.java.io :as io]
            [io.sixtant.secrets :refer :all])
  (:import (clojure.lang ExceptionInfo)
           (java.io File)))


(def ^:dynamic *temp-files* [])


(defn temp
  "Return the path to a temporary file with the given `prefix` and `suffix`."
  [prefix suffix]
  (let [p (.getCanonicalPath (File/createTempFile prefix suffix))]
    (try
      (set! *temp-files* (conj *temp-files* p))
      (catch IllegalStateException _
        (throw (ex-info "`temp` called outside of `with-temp-files`" {}))))
    p))


(defmacro with-temp-files
  "Ensure the deletion of any temp files created via `temp`."
  [& body]
  `(binding [*temp-files* []]
     (try
       (do ~@body)
       (finally
         (run!
           (fn [path#] (.delete (io/file path#)))
           *temp-files*)))))


(deftest encrypt-decrypt-test
  (let [data "secret data"
        pass "pass"]
    (testing "Encrypted data can be decrypted with the same password"
      (is (= data (decrypt (encrypt data pass) pass))))
    (testing "Encrypted data cannot be decrypted with a different password"
      (is (thrown? ExceptionInfo (decrypt (encrypt data pass) "different"))))))


(deftest encrypt-to-disk-test
  (with-temp-files
    (let [temp (temp "encrypted" ".edn")
          conf {:password "pass" :path temp}
          data {:bitso {:production {:key "foo" :secret "bar"}}}]
      (testing "Encryption & persistence of Clojure data structures"
        (encrypt-to-disk data conf)
        (is (not= (read-string (slurp temp)) data) "Data encrypted on disk")
        (is (= (decrypt-from-disk conf) data) "Can be decrypted")))))


(deftest high-level-api-test
  (with-temp-files
    (let [temp (temp "encrypted" ".edn")
          data {:bitso {:prod {:key "foo" :secret "bar"}}}]

      ; Write data to a temporary secrets file
      (with-path temp
        (write-secrets {:data data :password "pass"}))

      (with-password "pass"
        (with-path temp
          (with-secrets
            (is (= (secrets :bitso :prod :key) "foo"))))))))
