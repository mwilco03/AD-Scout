@{
    # Score Thresholds for Severity Classification
    # These values determine how findings are categorized by severity
    ScoreThresholds = @{
        Critical = 50    # Score >= 50 is Critical
        High     = 30    # Score >= 30 is High
        Medium   = 15    # Score >= 15 is Medium
        Low      = 5     # Score >= 5 is Low
        Info     = 0     # Score >= 0 is Informational
    }

    # Time-based Thresholds (in days)
    TimeThresholds = @{
        InactiveUserDays       = 90    # Days before user is considered inactive
        InactiveComputerDays   = 90    # Days before computer is considered inactive
        StalePasswordDays      = 365   # Days before password is considered stale
        CertificateExpiryDays  = 30    # Days before certificate expiry warning
        SignInLogRetentionDays = 7     # Days of sign-in logs to analyze
        RecentChangeDays       = 30    # Days to consider a change "recent"
    }

    # Count Thresholds for Privileged Access
    CountThresholds = @{
        AdminWarning  = 5     # Warning if more than this many admins
        AdminCritical = 10    # Critical if more than this many admins
        GroupMembershipWarning = 15    # Warning for excessive group membership
    }

    # Scanner Configuration
    ScannerDefaults = @{
        SMBPort           = 445
        LDAPSPort         = 636
        LDAPPort          = 389
        KerberosPort      = 88
        DefaultTimeoutMs  = 5000
        MinTimeoutMs      = 1000
        MaxTimeoutMs      = 60000
    }

    # Statistical Analysis
    StatisticsDefaults = @{
        ZScoreThreshold         = 2.0    # 95th percentile
        ZScoreCriticalThreshold = 3.0    # 99th percentile
        IQRMultiplier          = 1.5     # Standard IQR outlier detection
    }

    # JSON Serialization
    JsonDefaults = @{
        DefaultDepth = 20
        MaxDepth     = 30
    }

    # Categories - Single source of truth for all category lists
    Categories = @(
        'Anomalies'
        'AttackVectors'
        'Authentication'
        'DataProtection'
        'EntraID'
        'EphemeralPersistence'
        'GPO'
        'Infrastructure'
        'Kerberos'
        'LateralMovement'
        'Logging'
        'PKI'
        'Persistence'
        'PrivilegedAccess'
        'ServiceAccounts'
        'StaleObjects'
        'Trusts'
    )

    # Category Prefixes for Rule IDs
    CategoryPrefixes = @{
        Anomalies            = 'A'
        AttackVectors        = 'AV'
        Authentication       = 'AU'
        DataProtection       = 'DP'
        EntraID              = 'E'
        EphemeralPersistence = 'EP'
        GPO                  = 'G'
        Infrastructure       = 'I'
        Kerberos            = 'K'
        LateralMovement     = 'LM'
        Logging             = 'L'
        PKI                 = 'PKI'
        Persistence         = 'P'
        PrivilegedAccess    = 'PA'
        ServiceAccounts     = 'SA'
        StaleObjects        = 'S'
        Trusts              = 'T'
    }
}
