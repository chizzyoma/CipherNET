;; Title: CipherNET Nexus Protocol

;; Overview: Enhanced decentralized messaging protocol with optimized security, privacy, and batch processing

;; Error Codes
(define-constant ERR_ITEM_NOT_FOUND (err u100))
(define-constant ERR_DUPLICATE_ENTRY (err u101))
(define-constant ERR_ACCESS_DENIED (err u102))
(define-constant ERR_INVALID_PAYLOAD (err u103))
(define-constant ERR_USER_BLOCKED (err u104))
(define-constant ERR_ACCOUNT_SUSPENDED (err u105))
(define-constant ERR_RATE_LIMIT_HIT (err u106))
(define-constant ERR_BATCH_OVERFLOW (err u107))
(define-constant ERR_BATCH_TIMEOUT (err u108))
(define-constant ERR_INVALID_USERNAME (err u109))
(define-constant ERR_INVALID_USER (err u110))

;; Status Constants
(define-constant ACCOUNT_SUSPENDED u0)
(define-constant ACCOUNT_ACTIVE u1)
(define-constant ACCOUNT_PENDING u2)

(define-constant CONNECTION_PENDING u0)
(define-constant CONNECTION_APPROVED u1)
(define-constant CONNECTION_RESTRICTED u2)

;; Rate Limits
(define-constant DAILY_MAX_ACTIONS u100)
(define-constant DAILY_MAX_CONNECTIONS u20)
(define-constant DAILY_MAX_UPDATES u24)
(define-constant RESET_PERIOD u86400) ;; 24-hour reset window

;; Batch Processing Constraints
(define-constant MIN_BATCH_THRESHOLD u10)
(define-constant MAX_BATCH_THRESHOLD u100)
(define-constant BATCH_LIFESPAN u3600) ;; 1-hour expiry

;; Data Structures
(define-map UserRegistry 
    principal 
    {
        username: (string-ascii 64),
        state: uint,
        created-on: uint,
        additional-data: (optional (string-utf8 256)),
        suspended-at: (optional uint),
        cryptographic-key: (optional (buff 32)),
        avatar-url: (optional (string-utf8 256))
    }
)

(define-map PrivacySettings
    principal
    {
        allow-contacts-view: bool,
        allow-status-view: bool,
        allow-metadata-view: bool,
        allow-last-seen-view: bool,
        allow-avatar-view: bool,
        encryption-enabled: bool,
        updated-on: uint
    }
)

(define-map ActionCounter
    principal
    {
        actions-count: uint,
        connection-requests: uint,
        updates-count: uint,
        last-reset-time: uint
    }
)

(define-map MessageBatchTracker
    principal
    {
        messages-sent: uint,
        last-batch-time: uint,
        batch-capacity: uint,
        items-in-batch: uint,
        total-batches: uint
    }
)

(define-map UserEngagement
    principal
    {
        last-online: uint,
        login-frequency: uint,
        action-total: uint,
        latest-activity: uint
    }
)

(define-map ConnectionRecords
    {
        participant-a: principal,
        participant-b: principal
    }
    {
        status: uint
    }
)

(define-map RestrictionLog
    {
        restrictor: principal,
        restricted: principal
    }
    {
        logged-at: uint
    }
)

;; Public time function - to replace get-block-info?
(define-public (get-current-time)
    (ok u0)) ;; This will be replaced by the actual block time when deployed

;; Helper functions for min and max operations
(define-private (max-uint (a uint) (b uint))
    (if (>= a b) a b))

(define-private (min-uint (a uint) (b uint))
    (if (<= a b) a b))

;; Input validation functions
(define-private (validate-username (username (string-ascii 64)))
    (let ((len (len username)))
        (and 
            (>= len u3) 
            (<= len u64)
            ;; Additional validation could be added here
            true
        )
    )
)

(define-private (validate-principal (user principal))
    (and 
        (not (is-eq user tx-sender)) ;; Basic check to prevent self-operations
        ;; Check if the user exists in the registry
        (is-some (map-get? UserRegistry user))
        ;; Check if the user is not suspended
        (match (map-get? UserRegistry user)
            user-data (is-eq (get state user-data) ACCOUNT_ACTIVE)
            false
        )
    )
)

;; Safely get batch data with validation
(define-private (get-valid-batch-data (actor principal) (current-time uint))
    (let ((batch-data (default-to
            {
                messages-sent: u0,
                last-batch-time: current-time,
                batch-capacity: MIN_BATCH_THRESHOLD,
                items-in-batch: u0,
                total-batches: u0
            }
            (map-get? MessageBatchTracker actor))))
        ;; Ensure batch capacity stays within valid bounds
        (merge batch-data {
            batch-capacity: (min-uint MAX_BATCH_THRESHOLD 
                (max-uint MIN_BATCH_THRESHOLD (get batch-capacity batch-data)))
        })
    )
)

;; Private Functions
(define-private (check-action-limits (actor principal) (action-type uint) (current-time uint))
    (let ((actor-limits (default-to 
                {
                    actions-count: u0,
                    connection-requests: u0,
                    updates-count: u0,
                    last-reset-time: current-time
                }
                (map-get? ActionCounter actor)))
          (should-reset (> (- current-time (get last-reset-time actor-limits)) RESET_PERIOD)))
        (if should-reset
            (begin
                (map-set ActionCounter actor
                    {
                        actions-count: u1,
                        connection-requests: (if (is-eq action-type u1) u1 u0),
                        updates-count: (if (is-eq action-type u2) u1 u0),
                        last-reset-time: current-time
                    }
                )
                true
            )
            (and
                (< (get actions-count actor-limits) DAILY_MAX_ACTIONS)
                (or 
                    (not (is-eq action-type u1))
                    (< (get connection-requests actor-limits) DAILY_MAX_CONNECTIONS)
                )
                (or
                    (not (is-eq action-type u2))
                    (< (get updates-count actor-limits) DAILY_MAX_UPDATES)
                )
            )
        )
    )
)

(define-private (log-user-activity (actor principal) (current-time uint))
    (let ((activity-data (default-to
                {
                    last-online: current-time,
                    login-frequency: u0,
                    action-total: u0,
                    latest-activity: current-time
                }
                (map-get? UserEngagement actor))))
        (map-set UserEngagement actor
            (merge activity-data {
                last-online: current-time,
                action-total: (+ (get action-total activity-data) u1),
                latest-activity: current-time
            })
        )
    )
)

;; User-facing functions
(define-public (register-user (username (string-ascii 64)))
    (let (
        (current-time (unwrap-panic (get-current-time)))
        (existing-user (map-get? UserRegistry tx-sender))
        (safe-username (unwrap! (as-max-len? username u64) ERR_INVALID_USERNAME))
    )
        ;; Check if username is valid with additional safety
        (asserts! (validate-username safe-username) ERR_INVALID_USERNAME)
        
        ;; Check for duplicate entry
        (asserts! (is-none existing-user) ERR_DUPLICATE_ENTRY)
        
        ;; Proceed with registration after all checks pass
        (map-set UserRegistry tx-sender
            {
                username: safe-username,
                state: ACCOUNT_ACTIVE,
                created-on: current-time,
                additional-data: none,
                suspended-at: none,
                cryptographic-key: none,
                avatar-url: none
            }
        )
        (map-set PrivacySettings tx-sender
            {
                allow-contacts-view: true,
                allow-status-view: true,
                allow-metadata-view: true,
                allow-last-seen-view: true,
                allow-avatar-view: true,
                encryption-enabled: false,
                updated-on: current-time
            }
        )
        (map-set MessageBatchTracker tx-sender
            {
                messages-sent: u0,
                last-batch-time: current-time,
                batch-capacity: MIN_BATCH_THRESHOLD,
                items-in-batch: u0,
                total-batches: u0
            }
        )
        (ok true)
    )
)

;; Optimized Batch Processing
(define-public (modify-batch-settings (actor principal))
    (let ((current-time (unwrap-panic (get-current-time))))
        ;; Validate actor is caller or has permission
        (asserts! (is-eq actor tx-sender) ERR_ACCESS_DENIED)
        
        (let ((valid-batch-data (get-valid-batch-data actor current-time))
              (time-passed (- current-time (get last-batch-time valid-batch-data)))
              (current-capacity (get batch-capacity valid-batch-data))
              (pending-items (get items-in-batch valid-batch-data)))
            (if (> time-passed BATCH_LIFESPAN)
                (begin
                    (map-set MessageBatchTracker actor
                        (merge valid-batch-data {
                            batch-capacity: (max-uint MIN_BATCH_THRESHOLD (/ current-capacity u2)),
                            items-in-batch: u0,
                            last-batch-time: current-time
                        })
                    )
                    (ok true)
                )
                (begin
                    (map-set MessageBatchTracker actor
                        (merge valid-batch-data {
                            batch-capacity: (min-uint MAX_BATCH_THRESHOLD 
                                (if (>= pending-items (/ current-capacity u2))
                                    (* current-capacity u2)
                                    current-capacity
                                ))
                        })
                    )
                    (ok true)
                )
            )
        )
    )
)

;; Connection Management
(define-public (request-connection (target-user principal))
    (let ((current-time (unwrap-panic (get-current-time))))
        ;; Validate target user with enhanced checks
        (asserts! (validate-principal target-user) ERR_INVALID_USER)
        
        ;; Check rate limits
        (asserts! (check-action-limits tx-sender u1 current-time) ERR_RATE_LIMIT_HIT)
        
        ;; Check for existing connection
        (asserts! (is-none (map-get? ConnectionRecords { 
            participant-a: tx-sender, 
            participant-b: target-user 
        })) ERR_DUPLICATE_ENTRY)
        
        ;; All checks passed, proceed with connection request
        (map-set ConnectionRecords 
            { participant-a: tx-sender, participant-b: target-user }
            { status: CONNECTION_PENDING }
        )
        (log-user-activity tx-sender current-time)
        (ok true)
    )
)

(define-public (approve-connection (requester principal))
    (let ((current-time (unwrap-panic (get-current-time)))
          (connection-key { participant-a: requester, participant-b: tx-sender }))
        ;; Validate requester with enhanced checks
        (asserts! (validate-principal requester) ERR_INVALID_USER)
        
        ;; Check if connection request exists
        (match (map-get? ConnectionRecords connection-key)
            connection-data (begin
                ;; Verify connection is in pending state
                (asserts! (is-eq (get status connection-data) CONNECTION_PENDING) ERR_INVALID_PAYLOAD)
                
                ;; Update connection status
                (map-set ConnectionRecords connection-key
                    { status: CONNECTION_APPROVED }
                )
                (log-user-activity tx-sender current-time)
                (ok true)
            )
            ERR_ITEM_NOT_FOUND
        )
    )
)