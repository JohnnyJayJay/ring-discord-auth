(ns ring-discord-auth.ring-test
  (:require [clojure.java.io :as io]
            [clojure.test :refer [deftest is testing]]
            [ring-discord-auth.ring :as interceptor]
            [ring-discord-auth.test-helpers :as test-helpers]))

(defn build-request
  ([timestamp body signature]
   (build-request timestamp body signature :post))
  ([timestamp body signature method]
   {:request-method method
    :headers {"x-signature-ed25519" signature
              "x-signature-timestamp" timestamp}
    :body (io/input-stream (.getBytes body))
    :character-encoding "utf8"}))

(deftest verify-request-test
  (let [key-pair (test-helpers/generate-keypair)
        signer (test-helpers/new-signer (:private key-pair))
        public-key-hex (test-helpers/bytes->hex (.getEncoded (:public key-pair)))
        interceptor-fn (interceptor/wrap-authenticate identity public-key-hex)
        timestamp "1625603592"
        body "this should be a json."
        signature (->> (str timestamp body) .getBytes (test-helpers/sign signer) test-helpers/bytes->hex)]
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
                 (select-keys [:status :headers :body]))))
      (is (= {:status 400, :headers {"Content-Type" "text/plain", "Allow" "POST"}, :body "Missing body, signature or timestamp."}
             (-> (interceptor-fn (build-request nil
                                                ""
                                                nil))
                 (select-keys [:status :headers :body]))))
      (is (= {:status 405, :headers {"Content-Type" "text/plain", "Allow" "POST"}, :body "Only POST requests are allowed"}
             (-> (interceptor-fn (build-request nil
                                                ""
                                                nil
                                                :get))
                 (select-keys [:status :headers :body])))))))
