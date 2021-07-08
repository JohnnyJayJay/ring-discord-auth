(ns ring-discord-auth.core-test
  (:require [clojure.java.io :as io]
            [clojure.test :refer [deftest is testing]]
            [ring-discord-auth.core :as interceptor]
            [ring-discord-auth.validation :as validation]))

(defn build-request [timestamp body signature]
  {:request-method :post
   :headers {"x-signature-ed25519" signature
             "x-signature-timestamp" timestamp}
   :body (io/input-stream (.getBytes body))
   :character-encoding "utf8"})

(deftest verify-request-test
  (let [key-pair (validation/generate-keypair)
        signer (validation/new-signer (:private key-pair))
        public-key-hex (validation/bytes->hex (.getEncoded (:public key-pair)))
        interceptor-fn (interceptor/wrap-authenticate identity public-key-hex)
        timestamp "1625603592"
        body "this should be a json."
        signature (->> (str timestamp body) .getBytes (validation/sign signer) validation/bytes->hex)]
    (testing "interceptor should check signature vs public-key, timestamp and body"
      (is (= {:request-method :post :character-encoding "utf8"}
             (-> (interceptor-fn (build-request timestamp
                                                body
                                                signature))
                 (select-keys [:request-method :character-encoding]))))
      (is (= {:status 401, :headers {"Content-Type" "text/plain", "Allow" "POST"}, :body "Signature was not authentic."}
             (-> (interceptor-fn (build-request timestamp
                                                (str body "hackedbody")
                                                signature))
                 (select-keys [:status :headers :body])))))))
