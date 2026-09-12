package com.idpartners.pa.authzen;

import com.pingidentity.pa.sdk.http.HttpStatus;
import com.pingidentity.pa.sdk.http.Response;
import com.pingidentity.pa.sdk.http.ResponseBuilder;

import java.util.Map;

/**
 * The real {@link ResponseFactory}: the SDK's ResponseBuilder, whose implementation the
 * engine registers at boot. Excluded from unit coverage for that reason and exercised by
 * the live-server run in demo/.
 */
final class PaResponses implements ResponseFactory {
    @Override
    public Response build(Verdict v) {
        HttpStatus status = HttpStatus.forCode(v.status);
        if (status == null) {
            status = new HttpStatus(v.status, "");
        }
        ResponseBuilder b = ResponseBuilder.newInstance(status).body(v.body);
        String contentType = null;
        for (Map.Entry<String, String> h : v.headers.entrySet()) {
            if (h.getKey().equalsIgnoreCase("Content-Type")) {
                contentType = h.getValue();
            } else {
                b.header(h.getKey(), h.getValue());
            }
        }
        if (contentType != null) {
            b.contentType(contentType);
        }
        for (Map.Entry<String, String> h : v.responseHeaders.entrySet()) {
            b.header(h.getKey(), h.getValue());
        }
        return b.build();
    }
}
