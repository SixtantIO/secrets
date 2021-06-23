(ns io.sixtant.secrets-test
  (:require [clojure.test :refer :all]
            [io.sixtant.secrets :refer :all])
  (:import (clojure.lang ExceptionInfo)
           (java.io File)))


(deftest encrypt-decrypt-test
  (let [data "secret data"
        pass "pass"]
    (testing "Encrypted data can be decrypted with the same password"
      (is (= data (decrypt (encrypt data pass) pass))))
    (testing "Encrypted data cannot be decrypted with a different password"
      (is (thrown? ExceptionInfo (decrypt (encrypt data pass) "different"))))))


(deftest encrypt-to-disk-test
  (let [temp (.getCanonicalPath (File/createTempFile "encrypted" ".edn"))
        conf {:password "pass" :path temp}
        data {:bitso {:production {:key "foo" :secret "bar"}}}]
    (testing "Encryption & persistence of Clojure data structures"
      (encrypt-to-disk data conf)
      (is (not= (read-string (slurp temp)) data) "Data encrypted on disk")
      (is (= (decrypt-from-disk conf) data) "Can be decrypted"))))
