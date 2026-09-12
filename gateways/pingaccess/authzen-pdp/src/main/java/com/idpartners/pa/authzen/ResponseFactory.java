package com.idpartners.pa.authzen;

import com.pingidentity.pa.sdk.http.Response;

/** Turns a verdict into a PingAccess response. A seam: the SDK's builder needs the engine. */
interface ResponseFactory {
    Response build(Verdict verdict);
}
