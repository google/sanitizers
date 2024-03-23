; Proves the validity of the stack ring buffer wrapping logic in
; HWAddressSanitizer.cpp
(declare-const ThreadLong (_ BitVec 64))
(declare-const N (_ BitVec 64))
(declare-const Size (_ BitVec 64))
(declare-const Off (_ BitVec 64))
(declare-const CurrentThreadLong (_ BitVec 64))
(declare-const NextThreadLong (_ BitVec 64))

(define-fun Step ((ThreadLong (_ BitVec 64))) (_ BitVec 64)
        (bvand
            (bvxor
                (bvshl
                    (bvashr ThreadLong #x0000000000000038)
                    #x000000000000000c
                )
                #xFFFFFFFFFFFFFFFF
            )
            (bvadd ThreadLong #x0000000000000008)
        )
)

; Offset is aligned to 8 bytes.
(assert
  (=
    #x0000000000000000
    (bvand Off #x0000000000000007)
  )
)
; N is between 0 and 6 inclusive.
(assert (bvuge N #x0000000000000000))
(assert (bvult N #x0000000000000007))
; Size is 2**N * 4096
(assert (= Size (bvmul (bvshl #x0000000000000001 N) #x0000000000001000)))
; Size in pages is the top byte of ThreadLong
(assert (= (bvlshr ThreadLong #x0000000000000038) (bvshl #x0000000000000001 N)))
; ThreadLong is aligned to 2 * size
(assert
  (=
    #x0000000000000000
    (bvand ThreadLong (bvsub (bvmul Size #x0000000000000002) #x0000000000000001))
  )
)
; Current offset is within range
(assert (bvult Off Size))
(assert (= CurrentThreadLong (bvadd ThreadLong Off)))
(assert (= NextThreadLong (Step CurrentThreadLong)))
(echo "sat if OK, for sanity check of possible values")
(check-sat)
(get-model)
(push)

(assert (not
  (=
    NextThreadLong
    (if (= (bvadd Off #x0000000000000008) Size)
        ThreadLong
        (bvadd CurrentThreadLong #x0000000000000008)
    )
 )
))
(echo "unsat if OK")
(check-sat)
