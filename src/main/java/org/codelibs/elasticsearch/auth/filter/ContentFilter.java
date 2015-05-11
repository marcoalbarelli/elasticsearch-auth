package org.codelibs.elasticsearch.auth.filter;

import org.apache.lucene.search.Query;
import org.apache.lucene.util.BytesRef;
import org.codelibs.elasticsearch.auth.security.LoginConstraint;
import org.codelibs.elasticsearch.auth.service.AuthService;
import org.codelibs.elasticsearch.auth.util.ResponseUtil;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.netty.buffer.ChannelBuffer;
import org.elasticsearch.common.netty.channel.Channel;
import org.elasticsearch.http.HttpRequest;
import org.elasticsearch.http.netty.NettyHttpRequest;
import org.elasticsearch.index.query.QueryParseContext;
import org.elasticsearch.index.query.QueryParser;
import org.elasticsearch.index.query.QueryParsingException;
import org.elasticsearch.rest.*;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.channels.GatheringByteChannel;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

public class ContentFilter extends RestFilter {
    private static final ESLogger logger = Loggers
            .getLogger(ContentFilter.class);

    private volatile LoginConstraint[] constraints = null;

    private AuthService authService;

    private AtomicBoolean initializing = new AtomicBoolean(false);

    public ContentFilter(final AuthService authService) {
        this.authService = authService;
    }

    @Override
    public void process(final RestRequest request, final RestChannel channel,
            final RestFilterChain filterChain) {

        try {


            final String decoded = new String(request.content().toBytes(), "UTF-8");
            String lines[] = decoded.split("\\r?\\n");
            logger.error("On path " + request.uri() + " "+lines.length+" queries: ");

            for (String line : lines) {
                logger.error(line);
            }



        } catch(IOException ioe){
            logger.error(ioe.getMessage());
        }
        if (constraints == null) {
            init(request, channel, filterChain);
        } else {
            processNext(request, channel, filterChain);
        }
    }

    protected void init(final RestRequest request, final RestChannel channel,
            final RestFilterChain filterChain) {
        if (logger.isDebugEnabled()) {
            logger.debug("initializing: {0}", initializing);
        }
        if (!initializing.getAndSet(true)) {
            authService.init(new ActionListener<Void>() {
                @Override
                public void onResponse(final Void response) {
                    initializing.set(false);
                    if (constraints == null) {
                        sendServiceUnavailable(request, channel);
                    } else {
                        processNext(request, channel, filterChain);
                    }
                }

                @Override
                public void onFailure(final Throwable e) {
                    initializing.set(false);
                    logger.warn("Failed to reload AuthService.", e);
                    sendServiceUnavailable(request, channel);
                }
            });
        } else {
            sendServiceUnavailable(request, channel);
        }
    }

    protected void processNext(final RestRequest request,
            final RestChannel channel, final RestFilterChain filterChain) {
        final String rawPath = request.rawPath();
        for (final LoginConstraint constraint : constraints) {
            if (constraint.match(rawPath)) {
                if (logger.isDebugEnabled()) {
                    logger.debug(rawPath + " is filtered.");
                }

                final String token = authService.getToken(request);
                authService.authenticate(token,
                        constraint.getRoles(request.method()),
                        new ActionListener<Boolean>() {

                            @Override
                            public void onResponse(final Boolean isAuthenticated) {
                                if (isAuthenticated) {
                                    filterChain.continueProcessing(request,
                                            channel);
                                } else {
                                    // invalid
                                    ResponseUtil.send(request, channel,
                                            RestStatus.FORBIDDEN, "message",
                                            "Forbidden. Not authorized.");
                                }
                            }

                            @Override
                            public void onFailure(final Throwable e) {
                                logger.error("Authentication failed: token: "
                                        + token, e);
                                ResponseUtil.send(request, channel,
                                        RestStatus.FORBIDDEN, "message",
                                        "Forbidden. Authentication failed.");
                            }
                        });
                return;
            }
        }
        filterChain.continueProcessing(request, channel);
    }

    protected void sendServiceUnavailable(final RestRequest request,
            final RestChannel channel) {
        ResponseUtil.send(request, channel, RestStatus.SERVICE_UNAVAILABLE,
                "message", "A service is not available.");
        return;
    }

    public void setLoginConstraints(final LoginConstraint[] constraints) {
        this.constraints = constraints;
    }

}
