package netty.httpsserver;

import java.io.File;

import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslHandler;

public class HttpsServerInitializer extends ChannelInitializer<SocketChannel> {

    public static SslContext getSslContext() throws Exception {
        File certChainFile = new File("/Users/hezeyu/Documents/Netty/cert/server.crt");
        File keyFile = new File("/Users/hezeyu/Documents/Netty/cert/ca.key");
        File rootFile = new File("/Users/hezeyu/Documents/Netty/cert/ca.crt");
        SslContext sslCtx = SslContextBuilder.forServer(certChainFile, keyFile)
            .trustManager(rootFile).protocols("TLSv.1.2")
            .clientAuth(ClientAuth.NONE).build();
        return sslCtx;
    }

    @Override
    protected void initChannel(SocketChannel channel) throws Exception {
        SslHandler sslHandler = SSLHandlerProvider.getSSLHandler();

        ChannelPipeline pipeline = channel.pipeline();
        pipeline.addLast(sslHandler);
        //pipeline.addLast(getSslContext().newHandler(channel.alloc()));
        pipeline.addLast(new HttpServerCodec());
        pipeline.addLast("httpAggregator",new HttpObjectAggregator(512*1024));
        pipeline.addLast(new HttpsRequestHandler());
    }
}

