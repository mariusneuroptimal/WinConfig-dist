@{
    # R2 upload configuration — credentials injected at publish time by CI.
    # This file in source contains placeholders only; real values live in GitHub secrets.
    #
    # R2        = Bluetooth diagnostics channel (bucket winconfig-diagnostics). DO NOT RENAME.
    # SupportR2 = Support bundle channel (bucket winconfig-support) — SUPPORT-PROBE-001 §12.
    #             MUST stay a separate bucket: the BT ingest pipeline lists the whole
    #             winconfig-diagnostics bucket and would try to parse support ZIPs.
    R2 = @{
        AccountId   = 'f1a5f21df12cd7ca88df390a2b106037'
        BucketName  = 'winconfig-diagnostics'
        AccessKeyId = 'PLACEHOLDER'
        SecretKey   = 'PLACEHOLDER'
    }
    SupportR2 = @{
        AccountId   = 'f1a5f21df12cd7ca88df390a2b106037'
        BucketName  = 'winconfig-support'
        AccessKeyId = 'PLACEHOLDER'
        SecretKey   = 'PLACEHOLDER'
    }
}
