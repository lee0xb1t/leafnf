#include "redirectctx.h"

REDIRECT_CONTEXT* g_TcpRedirectCtx = NULL;
EX_PUSH_LOCK g_TcpRdCtxPushLock;

REDIRECT_CONTEXT* g_UdpRedirectCtx = NULL;
EX_PUSH_LOCK g_UdpRdCtxPushLock;

NTSTATUS RedirectCtxInit() {
    NTSTATUS status = STATUS_SUCCESS;

    // Initialized lock
    ExInitializePushLock(&g_TcpRdCtxPushLock);
    ExInitializePushLock(&g_UdpRdCtxPushLock);

    g_TcpRedirectCtx = ExAllocatePool3(POOL_FLAG_NON_PAGED, sizeof(REDIRECT_CONTEXT), 'xtcR', NULL, 0);
    if (!g_TcpRedirectCtx) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto end0;
    }

    g_UdpRedirectCtx = ExAllocatePool3(POOL_FLAG_NON_PAGED, sizeof(REDIRECT_CONTEXT), 'xtcR', NULL, 0);
    if (!g_UdpRedirectCtx) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto end0;
    }

    RtlZeroMemory(g_TcpRedirectCtx, sizeof(REDIRECT_CONTEXT));
    RtlZeroMemory(g_UdpRedirectCtx, sizeof(REDIRECT_CONTEXT));

    g_TcpRedirectCtx->proto_type = RC_PROTO_TYPE_TCP;
    g_UdpRedirectCtx->proto_type = RC_PROTO_TYPE_UDP;

    // bypass
    g_TcpRedirectCtx->nr_bypass_total = RC_DEFAULT_NR_PID;
    g_TcpRedirectCtx->bypass_pids = ExAllocatePool3(POOL_FLAG_NON_PAGED, sizeof(HANDLE) * RC_DEFAULT_NR_PID, 'xtcR', NULL, 0);
    if (!g_TcpRedirectCtx->bypass_pids) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto end0;
    }

    g_UdpRedirectCtx->nr_bypass_total = RC_DEFAULT_NR_PID;
    g_UdpRedirectCtx->bypass_pids = ExAllocatePool3(POOL_FLAG_NON_PAGED, sizeof(HANDLE) * RC_DEFAULT_NR_PID, 'xtcR', NULL, 0);
    if (!g_UdpRedirectCtx->bypass_pids) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto end0;
    }

    // proxy
    g_TcpRedirectCtx->nr_proxy_total = RC_DEFAULT_NR_PID;
    g_TcpRedirectCtx->proxy_pids = ExAllocatePool3(POOL_FLAG_NON_PAGED, sizeof(HANDLE) * RC_DEFAULT_NR_PID, 'xtcR', NULL, 0);
    if (!g_TcpRedirectCtx->proxy_pids) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto end0;
    }

    g_UdpRedirectCtx->nr_proxy_total = RC_DEFAULT_NR_PID;
    g_UdpRedirectCtx->proxy_pids = ExAllocatePool3(POOL_FLAG_NON_PAGED, sizeof(HANDLE) * RC_DEFAULT_NR_PID, 'xtcR', NULL, 0);
    if (!g_UdpRedirectCtx->proxy_pids) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto end0;
    }

end0:
    if (!NT_SUCCESS(status)) {
        if (g_TcpRedirectCtx) {
            if (g_TcpRedirectCtx->bypass_pids) {
                ExFreePoolWithTag(g_TcpRedirectCtx->bypass_pids, 'xtcR');
            }
            if (g_TcpRedirectCtx->proxy_pids) {
                ExFreePoolWithTag(g_TcpRedirectCtx->proxy_pids, 'xtcR');
            }
            ExFreePoolWithTag(g_TcpRedirectCtx, 'xtcR');
            g_TcpRedirectCtx = NULL;
        }

        if (g_UdpRedirectCtx) {
            if (g_UdpRedirectCtx->bypass_pids) {
                ExFreePoolWithTag(g_UdpRedirectCtx->bypass_pids, 'xtcR');
            }
            if (g_UdpRedirectCtx->proxy_pids) {
                ExFreePoolWithTag(g_UdpRedirectCtx->proxy_pids, 'xtcR');
            }
            ExFreePoolWithTag(g_UdpRedirectCtx, 'xtcR');
            g_UdpRedirectCtx = NULL;
        }
    }

    return status;
}

VOID RedirectCtxDestroy() {
    if (g_TcpRedirectCtx) {
        if (g_TcpRedirectCtx->bypass_pids) {
            ExFreePoolWithTag(g_TcpRedirectCtx->bypass_pids, 'xtcR');
        }
        if (g_TcpRedirectCtx->proxy_pids) {
            ExFreePoolWithTag(g_TcpRedirectCtx->proxy_pids, 'xtcR');
        }
        ExFreePoolWithTag(g_TcpRedirectCtx, 'xtcR');
        g_TcpRedirectCtx = NULL;
    }

    if (g_UdpRedirectCtx) {
        if (g_UdpRedirectCtx->bypass_pids) {
            ExFreePoolWithTag(g_UdpRedirectCtx->bypass_pids, 'xtcR');
        }
        if (g_UdpRedirectCtx->proxy_pids) {
            ExFreePoolWithTag(g_UdpRedirectCtx->proxy_pids, 'xtcR');
        }
        ExFreePoolWithTag(g_UdpRedirectCtx, 'xtcR');
        g_UdpRedirectCtx = NULL;
    }
}

VOID RedirectCtxSetProtoType(RC_PROTO_TYPE ProtocolType, RC_PROXY_TYPE ProxyType) {
    PEX_PUSH_LOCK pLock = (ProtocolType == RC_PROTO_TYPE_TCP)
        ? &g_TcpRdCtxPushLock
        : &g_UdpRdCtxPushLock;

    ExAcquirePushLockExclusive(pLock);

    if (ProtocolType == RC_PROTO_TYPE_TCP) {
        g_TcpRedirectCtx->proxy_type = ProxyType;
    } else {
        NT_ASSERT(ProtocolType == RC_PROTO_TYPE_UDP);
        g_UdpRedirectCtx->proxy_type = ProxyType;
    }

    ExReleasePushLockExclusive(pLock);
}

NTSTATUS RedirectCtxAddPid(RC_PROTO_TYPE ProtocolType, RC_PID_TYPE PidType, const HANDLE pid) {
    NTSTATUS status = STATUS_SUCCESS;

    REDIRECT_CONTEXT* ctx = NULL;

    PUINT32 pTotal = 0;
    PUINT32 pCount = 0;
    HANDLE** pArray = NULL;

    PEPROCESS process = NULL;

    if (ProtocolType == RC_PROTO_TYPE_TCP) {
        ctx = g_TcpRedirectCtx;
    } else {
        NT_ASSERT(ProtocolType == RC_PROTO_TYPE_UDP);
        ctx = g_UdpRedirectCtx;
    }

    NT_ASSERT(ctx != NULL);

    PEX_PUSH_LOCK pLock = (ProtocolType == RC_PROTO_TYPE_TCP)
        ? &g_TcpRdCtxPushLock
        : &g_UdpRdCtxPushLock;

    status = PsLookupProcessByProcessId(pid, &process);
    if (!NT_SUCCESS(status)) {
        goto end1;
    }


    ExAcquirePushLockExclusive(pLock);

    if (PidType == RC_PID_TYPE_BYPASS) {
        if (!ctx->bypass_pids) {
            goto end0;
        }

        pTotal = &ctx->nr_bypass_total;
        pCount = &ctx->nr_bypass;
        pArray = &ctx->bypass_pids;
    } else {
        NT_ASSERT(PidType == RC_PID_TYPE_PROXY);
        if (!ctx->proxy_pids) {
            goto end0;
        }

        pTotal = &ctx->nr_proxy_total;
        pCount = &ctx->nr_proxy;
        pArray = &ctx->proxy_pids;
    }

    for (UINT32 i = 0; i < *pCount; i++) {
        if (pid == (*pArray)[i]) {
            status = STATUS_SUCCESS;
            goto end0;
        }
    }

    // expand
    if (*pCount >= *pTotal) {
        UINT32 newTotal = (*pTotal == 0) ? RC_DEFAULT_NR_PID : *pTotal * 2;
        HANDLE* newBuffer = ExAllocatePool3(POOL_FLAG_NON_PAGED, sizeof(HANDLE) * newTotal, 'xtcR', NULL, 0);

        if (!newBuffer) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto end0;
        }

        RtlCopyMemory(newBuffer, *pArray, sizeof(HANDLE) * (*pCount));

        PVOID oldPtr = *pArray;

        *pArray = newBuffer;
        *pTotal = newTotal;

        ExFreePoolWithTag(oldPtr, 'xtcR');
    }

    (*pArray)[(*pCount)++] = pid;

end0:
    ExReleasePushLockExclusive(pLock);

    if (process) {
        ObDereferenceObject(process);
    }
end1:
    return status;
}

NTSTATUS RedirectCtxAddBypassPid(RC_PROTO_TYPE ProtocolType, const HANDLE pid) {
    return RedirectCtxAddPid(ProtocolType, RC_PID_TYPE_BYPASS, pid);
}

NTSTATUS RedirectCtxAddProxyPid(RC_PROTO_TYPE ProtocolType, const HANDLE pid) {
    return RedirectCtxAddPid(ProtocolType, RC_PID_TYPE_PROXY, pid);
}

BOOL RedirectCtxIsBypassProcess(RC_PROTO_TYPE ProtocolType, const HANDLE pid) {
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS process = NULL;
    REDIRECT_CONTEXT* ctx = NULL;
    PEX_PUSH_LOCK pLock = NULL;
    BOOL IsExists = FALSE;

    status = PsLookupProcessByProcessId(pid, &process);
    if (!NT_SUCCESS(status)) {
        goto end1;
    }

    if (ProtocolType == RC_PROTO_TYPE_TCP) {
        ctx = g_TcpRedirectCtx;
        pLock = &g_TcpRdCtxPushLock;
    } else {
        NT_ASSERT(ProtocolType == RC_PROTO_TYPE_UDP);
        ctx = g_UdpRedirectCtx;
        pLock = &g_UdpRdCtxPushLock;
    }

    ExAcquirePushLockShared(pLock);

    for (UINT32 i = 0; i < ctx->nr_bypass; i++) {
        if (pid == ctx->bypass_pids[i]) {
            IsExists = TRUE;
            goto end0;
        }
    }

end0:
    ExReleasePushLockShared(pLock);
    
    if (process) {
        ObDereferenceObject(process);
    }
end1:
    return IsExists;
}

BOOL RedirectCtxIsProxyProcess(RC_PROTO_TYPE ProtocolType, const HANDLE pid) {
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS process = NULL;
    REDIRECT_CONTEXT* ctx = NULL;
    PEX_PUSH_LOCK pLock = NULL;
    BOOL IsExists = FALSE;

    status = PsLookupProcessByProcessId(pid, &process);
    if (!NT_SUCCESS(status)) {
        goto end1;
    }

    if (ProtocolType == RC_PROTO_TYPE_TCP) {
        ctx = g_TcpRedirectCtx;
        pLock = &g_TcpRdCtxPushLock;
    } else {
        NT_ASSERT(ProtocolType == RC_PROTO_TYPE_UDP);
        ctx = g_UdpRedirectCtx;
        pLock = &g_UdpRdCtxPushLock;
    }

    ExAcquirePushLockShared(pLock);

    for (UINT32 i = 0; i < ctx->nr_proxy; i++) {
        if (pid == ctx->proxy_pids[i]) {
            IsExists = TRUE;
            goto end0;
        }
    }

end0:
    ExReleasePushLockShared(pLock);

    if (process) {
        ObDereferenceObject(process);
    }
end1:
    return IsExists;
}

RC_PROXY_TYPE RedirectCtxGetProtoType(RC_PROTO_TYPE ProtocolType) {
    RC_PROXY_TYPE proxy_type;

    PEX_PUSH_LOCK pLock = (ProtocolType == RC_PROTO_TYPE_TCP)
        ? &g_TcpRdCtxPushLock
        : &g_UdpRdCtxPushLock;

    ExAcquirePushLockShared(pLock);
    
    if (ProtocolType == RC_PROTO_TYPE_TCP) {
        proxy_type = g_TcpRedirectCtx->proxy_type;
    } else {
        NT_ASSERT(ProtocolType == RC_PROTO_TYPE_UDP);
        proxy_type = g_UdpRedirectCtx->proxy_type;
    }

    ExReleasePushLockShared(pLock);

    return proxy_type;
}