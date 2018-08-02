(ns metabase.query-processor.middleware.decode_result
    "Middleware for catching exceptions thrown by the query processor and returning them in a friendlier format."
    (:require [metabase.query-processor.middleware
               [source-table :as source-table]]
              [metabase.query-processor.util :as qputil]
              [clojure.tools.logging :as log]
              [metabase.util :as u]
              schema.utils)
    (:import [schema.utils NamedError ValidationError]
        [javax.crypto Cipher KeyGenerator SecretKey]
        [javax.crypto.spec  SecretKeySpec]
        [java.security  SecureRandom]))

(defn get-bytes [s]
    (.getBytes s "UTF-8"))

(defn hexify [s]
    (apply str (map #(format "%02x" %) (get-bytes s))))
      
(defn unhexify [s]
    (let [bytes (into-array Byte/TYPE
                    (map (fn [[x y]]
                        (unchecked-byte (Integer/parseInt (str x y) 16)))
                            (partition 2 s)))]
        bytes))
        
        
(defn get-raw-key [seed]
    (let [keygen (KeyGenerator/getInstance "AES")
            sr (SecureRandom/getInstance "SHA1PRNG")]
        (.setSeed sr (get-bytes seed))
        (.init keygen 128 sr)
        (.. keygen generateKey getEncoded)))
          
(defn get-cipher [mode seed]
    (let [key-spec (SecretKeySpec. (get-bytes seed) "AES")
        cipher (Cipher/getInstance "AES")]
    (.init cipher mode key-spec)
    cipher))

(defn encrypt [text key]
    (let [bytes (get-bytes text)
            cipher (get-cipher Cipher/ENCRYPT_MODE key)]
        (hexify (.doFinal cipher bytes))))

(defn decrypt [text key]
    (let [cipher (get-cipher Cipher/DECRYPT_MODE key)]
        (String. (.doFinal cipher (unhexify text)))))

(defn is-hexstr [s]
    (and (string? s) (some? (re-find #"^[0-9,a-f,A-F]{16,}$" s)))
    )
    
; (s/defn parse-druid-template [sql param-key->value]
;     (let [ori_query {:query sql}]
;         ; (assoc ori_query :query (replace_druid_params (get-in ori_query [:query]) "countrynn" "Russia" "location/country"))))
;         (reduce-kv (fn [m k v]
;                     (let [new-query (replace_druid_params (get-in m [:query]) (name k) (get-in v [:param :value]) (get-in v [:param :type]))]
;                     (log/info (u/format-color 'red "after replace_druid_params: new-query:%s" new-query))
;                     (assoc m :query new-query))) ori_query param-key->value)))

(defn- decode-data [data]
    (log/info (u/format-color 'red "begin decode_data:\n%s" data))
    (if (is-hexstr data)
        (try (decrypt data "!#Ai&N~lwQKnBcDA")
            (catch Throwable e
                data))
        data
    ))
    

(defn- decode-row [row] 
    (map decode-data row)
    )

(defn- decode-rows [results]
    (let [rows (get-in results [:data :rows])]
        (map decode-row rows)
        ))

(defn- decode_data [results]
    (assoc (get-in results [:data]) :rows (decode-rows results))
)
    
(defn decode
    [qp]
    (fn [query]
        (let [result (qp query)]
            (log/info (u/format-color 'red "begin decode:\n%s" result))
            (assoc result :data (decode_data result))))
        )