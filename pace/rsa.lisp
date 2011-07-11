(defun split-hex (str)
  (let ((next-colon (search ":" str)))
    (cond ((null next-colon)
	   (list (parse-integer str :radix 16)))
	  (t
	   (cons (parse-integer (subseq str 0 next-colon) :radix 16)
		 (split-hex (subseq str (1+ next-colon))))))))

(defun hex-val-le (bytes)
  (cond ((null bytes) 0)
	(t (+ (car bytes)
	      (* 256 (hex-val-le (cdr bytes)))))))

(defun parse-hex-be (str)
  (hex-val-le (reverse (split-hex str))))

(defun parse-hex-le (str)
  (hex-val-le (split-hex str)))

;(setq e #x10001)
;(setq p (parse-hex-be "00:ec:e6:12:9a:37:18:dc:fa:0d:1f:2b:53:28:60:e6:03:2c:88:03:b6:18:2b:9f:d2:10:21:a4:84:38:0b:52:71"))
;(setq q (parse-hex-be "00:d2:0a:dc:d2:a6:72:b1:70:88:1f:0b:ac:8b:a9:21:5f:52:ab:01:3b:a5:5b:22:d2:68:79:71:56:28:61:b1:f7"))
;(setq d (private-exponent e p q))
;(setq dmp1 (mod d (- p 1)))
;(setq dmq1 (mod d (- q 1)))
;(setq qinv (modulo-inverse q p))

(setq e 3)
(setq n (parse-hex-le "93:CE:A5:C8:7A:81:B5:5D:C7:6A:14:09:8D:30:D0:B5:FC:77:B9:BE:C6:1C:25:69:F5:10:68:9A:6D:A2:D4:DB:4F:9C:E7:1E:78:A2:9F:1E:C7:5F:98:07:DF:17:71:C0:C7:F5:BE:8B:6D:A6:BF:0F:23:E8:5C:15:46:74:0F:A5"))
(setq p (parse-hex-le "81:89:9F:E7:3F:F5:63:BF:49:6D:EC:B4:C5:EB:1E:E7:82:5A:99:AD:90:7E:E6:13:F5:94:6B:7E:2D:6D:5F:D1"))
(setq q (parse-hex-le "13:9A:97:84:66:B1:7F:1D:ED:D5:2A:63:EC:27:14:71:47:7E:02:5E:B1:9C:20:A7:59:58:41:B7:A3:BA:D1:C9"))

(setq d (private-exponent e p q))
(setq dmp1 (mod d (- p 1)))
(setq dmq1 (mod d (- q 1)))
(setq qinv (modulo-inverse q p))


;AB:5B:6A:9A:2A:4E:ED:D4:DB:48:48:23:D9:47:BF:44:57:3C:66:1E:0B:FF:EE:B7:F8:0D:9D:A9:73:F3:94:8B
;B7:66:BA:AD:99:CB:FF:68:F3:E3:71:97:9D:1A:B8:A0:2F:54:AC:3E:76:68:C0:C4:3B:90:2B:7A:C2:D1:8B:86
;0C:7A:88:27:18:38:61:05:AE:55:09:F7:49:0A:8C:50:0C:A9:72:3E:27:26:0D:30:67:C5:C5:D5:95:55:49:78

; simple rsa translated from
; http://matt.might.net/articles/implementation-of-rsa-public-key-cryptography-algorithm-in-scheme-dialect-of-lisp/

; Mathematical routines.

; extended-gcd(a,b) = (x,y), such that a*x + b*y = gcd(a,b)
(defun extended-gcd (a b)
  (if (= (mod a b) 0)
      (cons 0 1)
      (let* ((xy (extended-gcd b (mod a b)))
             (x (car xy))
             (y (cdr xy)))
        (cons y (- x (* y (floor a b)))))))

; modulo-inverse(a,n) = b, such that a*b = 1 [mod n].
(defun modulo-inverse (a n)
  (mod (car (extended-gcd a n)) n))

; totient(n) = (p - 1)*(q - 1), 
;  where pq is the prime factorization of n.
(defun totient (p q) (* (- p 1) (- q 1)))

; square(x) = x^2
(defun square (x) (* x x))

; modulo-power(base,exp,n) = base^exp [mod n]
(defun modulo-power (base exp n)
  (if (= exp 0)
      1
      (if (oddp exp)
          (mod (* base (modulo-power base (- exp 1) n)) n)
          (mod (square (modulo-power base (/ exp 2) n)) n))))

;; RSA routines.

; A legal public exponent e is between
;  1 and totient(n), and gcd(e,totient(n)) = 1
(defun is-legal-public-exponent? (e p q)
  (and (< 1 e) 
       (< e (totient p q))
       (= 1 (gcd e (totient p q)))))

; The private exponent is the inverse of the public exponent, mod n.
(defun private-exponent (e p q) 
  (if (is-legal-public-exponent? e p q)
      (modulo-inverse e (totient p q))
      (error "Not a legal public exponent for that modulus.")))

; An encrypted message is c = m^e [mod n].
(defun rsa-encrypt (m e n)
  (if (> m n)
      (error "The modulus is too small to encrypt the message.")
      (modulo-power m e n)))

; A decrypted message is m = c^d [mod n].
(defun rsa-decrypt (c d n)
  (modulo-power c d n))


;; RSA example.
;(setq p 41)       ; A "large" prime.
;(setq q 47)       ; Another "large" prime.
;(setq n (* p q))  ; The public modulus.
;(setq e 7)                        ; The public exponent.
;(setq d (private-exponent e p q)) ; The private exponent.
;(setq plaintext  42)           
;(setq ciphertext (rsa-encrypt plaintext e n)) 
;(setq decrypted-ciphertext (rsa-decrypt ciphertext d n))
;(format t "The plaintext is:            ")
;(format t "~s~%" plaintext)
;(format t "The ciphertext is:           ")
;(format t "~s~%" ciphertext)
;(format t "The decrypted ciphertext is: ")
;(format t "~s~%" decrypted-ciphertext)
;(if (not (= plaintext decrypted-ciphertext))
;    (error "RSA fail!"))

