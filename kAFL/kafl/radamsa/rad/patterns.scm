;;;
;;; Mutation patterns
;;;

(define-library (rad patterns)

   (import
      (owl toplevel)
      (rad shared)
      (rad pcapng))

   (export
      *patterns*
      default-patterns
      string->patterns)

   (begin

      (define null '())

      (define max-burst-mutations 16)
      (define max-mutation-retries 24)

      ;; check that byte vector bv from position bvp matches byte vector x from xp
      ;; if they do (exactly), return #true
      ;; if they don't, return #false
      ;; if x contains a prefix of bvp, return the corresponding position of bvec
      (define (walk-bytes bv bvp x xp)
         (let ((val (ref bv bvp)))
            (if val
               (let ((xval (ref x xp)))
                  (cond
                     ((eq? val xval)
                        (walk-bytes bv (+ bvp 1) x (+ xp 1)))
                     ((not xval)
                        ;; continues in the next block
                        bvp)
                     (else
                        ;; no match
                        #false)))
               (not (ref x xp))))) ;; xp should end too

      ;; note: need to change also tails
      ;; like equal?, but we want to make (#(1 2) #(3 4) ...) = (#(1 2 3 4) ...)
      (define (tail-after bvec lst)
         (let loop ((pos 0) (lst lst))
            (cond
               ((not (pair? lst))
                  ;; out of data
                  #f)
               ((walk-bytes bvec pos (car lst) 0)
                  => (lambda (pos)
                        (if (eq? pos #true)
                           (begin
                              ;(print "These were equal!")
                              (cdr lst))
                           (begin
                              ;(print "Prefix matched resuming " bvec " from pos " pos " against " (cdr lst))
                              (loop pos (cdr lst))))))
               (else
                  #false))))

      (define (changes-occurred? orig new)
         (let ((tail (tail-after (car orig) new)))
            (if tail
               (not (equal? (cdr orig) tail))
               #t)))

      (define (force-change mutator rs ll meta n)
         (if (pair? ll)
            (lets ((mutatorp rsp llp metap (mutator rs ll meta)))
               (cond
                  ;; this is kind of like (not (equal? ll llp)), but we want to allow the
                  ;; *first* byte vector of ll to become partitioned into separate ones at
                  ;; the beginning of llp
                  ((changes-occurred? ll llp)
                     (values mutatorp rsp llp
                        (put metap 'remutated n)))
                  ((eq? n 0)
                     (values mutatorp rsp llp
                        (put metap 'remutate-failed max-mutation-retries)))
                  (else
                     (force-change mutator rsp llp meta (- n 1)))))
            (force-change mutator rs (list (vector)) meta n)))

      (define (mutate-once rs ll mutator meta cont)
         (lets
            ((rs ip (rand rs initial-ip)) ;; initial inverse probability, magic value
             (this ll (uncons ll #false)))
            (if this
               (let loop ((rs rs) (this this) (ll ll) (ip ip))
                  (if (function? ll)
                     ;; stream more data
                     (loop rs this (ll) ip)
                     (lets ((rs n (rand rs ip)))
                        (if (and (or (eq? n 0) (null? ll)) ;; mutation happens to occur, or last place for it
                                 (or (not (eq? (get meta 'generator) 'pcapng))
                                     (pcapng-block-to-mutate? this)))
                           (lets
                              ((ll (cons this ll))
                               (mutator rs ll meta (force-change mutator rs ll meta max-mutation-retries)))
                              (cont ll rs mutator meta))
                           ;; keep moving
                           (if (null? ll)
                              (list this)
                              (pair this
                                 (loop rs (car ll) (cdr ll) (+ ip 1))))))))
               ;; no data to work on
               (cont null rs mutator meta))))

      ;; pat :: rs ll muta meta → ll' ++ (list (tuple rs mutator meta))
      (define (pat-once-dec rs ll mutator meta)
         (mutate-once rs ll mutator
            (put meta 'pattern 'once-dec)
            (λ (ll rs mutator meta)
               (lappend ll (list (tuple rs mutator meta))))))

      ;; 1 or more mutations
      (define (pat-many-dec rs ll mutator meta)
         (mutate-once rs ll mutator
            (put meta 'pattern 'many-dec)
            (λ (ll rs mutator meta)
               (lets ((rs muta? (rand-occurs? rs remutate-probability)))
                  (if muta?
                     (pat-many-dec rs ll mutator meta)
                     (lappend ll (list (tuple rs mutator meta))))))))

      (define (pat-burst rs ll mutator meta)
         (mutate-once rs ll mutator
            (put meta 'pattern 'burst)
            (λ (ll rs mutator meta)
               (let loop ((rs rs) (ll ll) (mutator mutator) (meta meta) (n 1))
                  (lets ((rs p (rand-occurs? rs remutate-probability)))
                     (if (or p (< n 2))
                        ;; note, the ll is pre-evaluated because we already mutated it
                        (lets ((mutator rs ll meta (force-change mutator rs ll meta max-mutation-retries)))
                           (loop rs ll mutator meta (+ n 1)))
                        (lappend ll (list (tuple rs mutator meta)))))))))

      (define *patterns*
         (list
            (tuple "od" pat-once-dec "Mutate once" )
            (tuple "nd" pat-many-dec "Mutate possibly many times" )
            (tuple "bu" pat-burst "Make several mutations closeby once")))

      (define default-patterns "od,nd=2,bu")

      (define (priority->pattern pri)
         (let ((func (choose *patterns* (car pri))))
            (if func
               (cons (cdr pri) func)
               (begin
                  (print*-to stderr (list "Unknown pattern: " (cdr pri)))
                  #false))))

      ;; ((pri . pat) ...) → (rs ll muta meta → <pattern output>)
      (define (mux-patterns ps)
         (lets
            ((ps (sort car> ps))
             (n (fold + 0 (map car ps))))
            (λ (rs ll muta meta)
               (lets ((rs n (rand rs n)))
                  ((choose-pri ps n) rs ll muta meta)))))

      (define cut-= (string->regex "c/=/"))
      (define cut-comma (string->regex "c/,/"))

      (define (string->patterns str)
         (lets
            ((ps (map cut-= (cut-comma str))) ; ((name [priority-str]) ..)
             (ps (map selection->priority ps))
             (ps (map priority->pattern ps)))
            (if (every self ps)
               (mux-patterns ps)
               #false)))
))

