/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.test;

import static java.net.HttpURLConnection.*;
import static org.junit.Assert.*;

import java.io.IOException;
import java.net.*;
import java.util.Objects;

import com.sun.net.httpserver.*;

import ghidra.util.Msg;

public class MockHttpServerUtils {
	private static int LAST_SERVER_PORT_NUM = 8000 + 5000;
	public static final String CONTENT_TYPE_HEADER = "Content-Type";

	/**
	 * Convert a mock http server's address to a URL
	 * 
	 * @param addr {@link InetSocketAddress}
	 * @return http connection URI, example "http://127.0.0.1:9999"
	 */
	public static URI getURI(InetSocketAddress addr) {
		return URI.create("http://%s:%d".formatted(addr.getHostString(), addr.getPort()));
	}

	/**
	 * {@return the next hopefully unused localhost socket addr}
	 */
	public static InetSocketAddress nextLoopbackServerAddr() {
		InetSocketAddress serverAddr =
			new InetSocketAddress(InetAddress.getLoopbackAddress(), LAST_SERVER_PORT_NUM);
		LAST_SERVER_PORT_NUM++; // don't try to reuse the same server port num in the same session
		return serverAddr;
	}

	/**
	 * Creates an HttpServer, listening on localhost and a unique unused port number.
	 * <p>
	 * Use {@link HttpServer#createContext(String, HttpHandler)} to add handlers for specific
	 * paths.
	 * 
	 * @return new {@link HttpServer}
	 * @throws IOException if unused port is not found
	 */
	public static HttpServer createMockHttpServer() throws IOException {
		IOException lastException = null;
		for (int retryNum = 0; retryNum < 10; retryNum++) {
			InetSocketAddress serverAddress = nextLoopbackServerAddr();

			try {
				HttpServer server = HttpServer.create(serverAddress, 0);
				return server;
			}
			catch (IOException e) {
				// ignore, just try again with next port num
				lastException = e;
			}
		}
		throw new IOException(
			"Could not allocate port for mock http server, last attempted port: " +
				LAST_SERVER_PORT_NUM,
			lastException);
	}

	/**
	 * Asserts that the specified {@link HttpExchange} has a specific content type header.
	 * 
	 * @param expectedType example: "application/json"
	 * @param httpExchange {@link HttpExchange}
	 */
	public static void assertContentType(String expectedType, HttpExchange httpExchange) {
		String contentType = httpExchange.getRequestHeaders().getFirst(CONTENT_TYPE_HEADER);
		contentType = Objects.requireNonNullElse(contentType, "missing");
		if (!expectedType.equals(contentType)) {
			fail("Content type incorrect: expected: %s, actual: %s".formatted(expectedType,
				contentType));
		}
	}

	/**
	 * Adds a delay to a handler.
	 * 
	 * @param delegate {@link HttpHandler} to wrap
	 * @param delayMS milliseconds to delay before allowing the delegate to process the request
	 * @return new HttpHandler that wraps the specified delegate
	 */
	public static HttpHandler wrapHandlerWithDelay(HttpHandler delegate, int delayMS) {
		return httpExchange -> {
			try {
				Thread.sleep(delayMS);
			}
			catch (InterruptedException e) {
				// ignore
			}
			delegate.handle(httpExchange);
		};
	}

	public static HttpHandler wrapHandlerWithRetryError(HttpHandler delegate, int errorCount,
			int errorStatus) {
		return new HttpHandler() {
			int errorNum;

			@Override
			public void handle(HttpExchange exchange) throws IOException {
				if (errorNum++ < errorCount) {
					exchange.sendResponseHeaders(errorStatus, 0);
					exchange.close();
					return;
				}
				delegate.handle(exchange);
			}
		};
	}

	/**
	 * A handler that always returns a 404.  Use this as the target of a lambda.  This matches
	 * the {@link HttpHandler#handle(HttpExchange)} method signature.
	 * 
	 * @param httpExchange {@link HttpExchange}
	 * @throws IOException if error
	 */
	public static void mock404Handler(HttpExchange httpExchange) throws IOException {
		try {
			httpExchange.sendResponseHeaders(HttpURLConnection.HTTP_NOT_FOUND, 0);
		}
		finally {
			httpExchange.close();
		}
	}

	/**
	 * Creates a HttpHandler that returns a specified body
	 * 
	 * @param contentType http content type header value (eg. "text/plain")
	 * @param resultBody bytes to send as body
	 * @return new HttpHandler
	 */
	public static HttpHandler createStaticResponseHandler(String contentType, byte[] resultBody) {
		return createStaticResponseHandler(HTTP_OK, contentType, resultBody);
	}

	/**
	 * Creates a HttpHandler that returns a specified body and result code.
	 * 
	 * @param resultCode http result code to return (eg. HTTP_OK / 200 )
	 * @param contentType http content type header value (eg. "text/plain")
	 * @param resultBody bytes to send as body
	 * @return new HttpHandler
	 */
	public static HttpHandler createStaticResponseHandler(int resultCode, String contentType,
			byte[] resultBody) {
		return httpExchange -> {
			try {
				byte[] actualResult =
					httpExchange.getRequestMethod().equals("GET") ? resultBody : null;
				httpExchange.getResponseHeaders().set(CONTENT_TYPE_HEADER, contentType);
				httpExchange.sendResponseHeaders(resultCode,
					actualResult != null ? actualResult.length : -1);
				if (actualResult != null) {
					httpExchange.getResponseBody().write(resultBody);
				}
			}
			catch (Throwable th) {
				logMockHttp(httpExchange,
					"Error during mockStaticResponseHandler: " + th.getMessage());
				throw th;
			}
			finally {
				httpExchange.close();
			}
		};
	}

	/**
	 * Logs (using Msg.info) a message using information from the http connection as a prefix
	 * 
	 * @param httpExchange {@link HttpExchange}
	 * @param msg string message
	 */
	public static void logMockHttp(HttpExchange httpExchange, String msg) {
		Msg.info(MockHttpServerUtils.class, "[%s %s] %s".formatted(httpExchange.getLocalAddress(),
			httpExchange.getRequestURI(), msg));

	}
}
