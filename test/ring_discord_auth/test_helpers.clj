(ns ring-discord-auth.test-helpers
  (:import (java.security SecureRandom)
           (org.bouncycastle.crypto.generators Ed25519KeyPairGenerator)
           (org.bouncycastle.crypto.params Ed25519KeyGenerationParameters Ed25519PrivateKeyParameters Ed25519PublicKeyParameters)
           (org.bouncycastle.crypto.signers Ed25519Signer)))

(defn generate-keypair
  "Generate Ed25519 key pair.

  Return {:private `Ed25519PrivateKeyParameters`
          :public `Ed25519PublicKeyParameters`}"
  []
  (let [random (SecureRandom.)
        kpg    (Ed25519KeyPairGenerator.)
        _ (.init kpg (Ed25519KeyGenerationParameters. random))
        key-pair (.generateKeyPair kpg)]
    {:private (cast Ed25519PrivateKeyParameters (.getPrivate key-pair))
     :public  (cast Ed25519PublicKeyParameters (.getPublic key-pair))}))

(defn new-signer
  "Return new instance of `Ed25519Signer` initialized by private key"
  [private-key]
  (let [signer (Ed25519Signer.)]
    (.init signer true private-key)
    signer))

(defn sign
  "Generate signature for msg byte array.

  Return byte array with signature."
  [^Ed25519Signer signer msg-bytes]
  (.update signer msg-bytes 0 (alength msg-bytes))
  (.generateSignature signer))
