(ns ring-discord-auth.core-test
  (:require [clojure.test :refer [deftest is testing]]
            [ring-discord-auth.core :as core]
            [ring-discord-auth.test-helpers :as test-helpers])
  (:import (org.bouncycastle.crypto.params Ed25519PublicKeyParameters)
           (org.bouncycastle.crypto.signers Ed25519Signer)))

(deftest public-key-verifier-test
  (let [public-key-str "e421dceefff3a9d008b7898fcc0974813201800419d72f36d51e010d6a0acb71"]
    (testing "public-key->verifier should convert all possible types or return nil"
      (is (instance? Ed25519Signer
                     (core/public-key->signer-verifier public-key-str)))

      (is (instance? Ed25519Signer
                     (core/public-key->signer-verifier (core/hex->bytes public-key-str))))

      (is (instance? Ed25519Signer
                     (core/public-key->signer-verifier (-> public-key-str
                                                           core/hex->bytes
                                                           (Ed25519PublicKeyParameters. 0)))))
      (is (instance? Ed25519Signer
                     (core/public-key->signer-verifier (-> public-key-str
                                                           core/hex->bytes
                                                           (Ed25519PublicKeyParameters. 0)
                                                           core/new-verifier))))
      (is (nil? (core/public-key->signer-verifier 1)))
      (is (nil? (core/public-key->signer-verifier nil))))))

(deftest authentic-test
  (let [key-pair (test-helpers/generate-keypair)
        signer (test-helpers/new-signer (:private key-pair))
        public-key (.getEncoded (:public key-pair))
        timestamp "1625603592"
        body "this should be a json."
        signature (->> (str timestamp body) .getBytes (test-helpers/sign signer))]
    (testing "authentic? should check signature vs public-key, timestamp and body"
      (is (= true
             (core/authentic? (test-helpers/bytes->hex signature)
                              body
                              timestamp
                              (test-helpers/bytes->hex public-key)
                              "utf8"))
          "checks with conversions.")
      (is (= true
             (core/authentic? signature
                              (.getBytes body)
                              (.getBytes timestamp)
                              public-key
                              "utf8"))
          "checks without conversions.")
      (is (= false
             (core/authentic? (test-helpers/bytes->hex signature)
                              (str body "hacks-to-fail")
                              timestamp
                              (test-helpers/bytes->hex public-key)
                              "utf8"))
          "checks with conversions.")
      (is (= false
             (core/authentic? signature
                              (.getBytes (str body "hacks-to-fail"))
                              (.getBytes timestamp)
                              public-key
                              "utf8"))
          "checks without conversions."))))
