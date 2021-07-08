(ns ring-discord-auth.validation-test
  (:require [clojure.test :refer [deftest is testing]]
            [ring-discord-auth.validation :as validation]))

(deftest verify-request-test
  (let [key-pair (validation/generate-keypair)
        signer (validation/new-signer (:private key-pair))
        public-key-hex (validation/bytes->hex (.getEncoded (:public key-pair)))
        timestamp "1625603592"
        body "this should be a json."
        signature (->> (str timestamp body) .getBytes (validation/sign signer) validation/bytes->hex)]
    (testing "verify-request should check signature vs public-key, timestamp and body"
      (is (= true
             (validation/verify-request public-key-hex
                                        timestamp
                                        body
                                        signature)))
      (is (= false
             (validation/verify-request public-key-hex
                                        timestamp
                                        "this should be a json.hacks"
                                        signature))))))