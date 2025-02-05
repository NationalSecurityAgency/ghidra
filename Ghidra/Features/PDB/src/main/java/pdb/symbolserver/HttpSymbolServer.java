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
package pdb.symbolserver;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.util.concurrent.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.net.HttpClients;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;
import pdb.symbolserver.SymbolServer.MutableTrust;

/**
 * A {@link SymbolServer} that is accessed via HTTP.
 * <p>
 * 
 */
public class HttpSymbolServer extends AbstractSymbolServer implements MutableTrust {
	private static final String GHIDRA_USER_AGENT = "Ghidra_HttpSymbolServer_client";
	private static final int HTTP_STATUS_OK = HttpURLConnection.HTTP_OK;
	private static final int HTTP_REQUEST_TIMEOUT_MS = 10 * 1000; // 10 seconds

	/**
	 * pattern to match an optional "!" in front of a typical url string
	 */
	private static final Pattern NAMEPAT = Pattern.compile("(\\!?)(http(s?)://.*)");

	/**
	 * Predicate that tests if the location string is an instance of a HttpSymbolServer location.
	 * 
	 * @param locationString symbol server location string
	 * @return boolean true if the string should be handled by the HttpSymbolServer class 
	 */
	public static boolean isHttpSymbolServerLocation(String locationString) {
		return NAMEPAT.matcher(locationString).matches();
	}

	/**
	 * Creates a new HttpSymbolServer instance from a locationString.
	 * 
	 * @param locationString string previously returned by {@link #getName()}
	 * @param context {@link SymbolServerInstanceCreatorContext} 
	 * @return new instance
	 */
	public static SymbolServer createInstance(String locationString,
			SymbolServerInstanceCreatorContext context) {
		Matcher m = NAMEPAT.matcher(locationString);
		if (!m.matches()) {
			return null;
		}
		boolean isTrusted = "!".equals(m.group(1));
		String url = m.group(2);
		return new HttpSymbolServer(URI.create(url), isTrusted);
	}

	/**
	 * Create a trusted http symbol server
	 * 
	 * @param url string url
	 * @return new {@link HttpSymbolServer} instance
	 */
	public static HttpSymbolServer createTrusted(String url) {
		return new HttpSymbolServer(URI.create(url), true);
	}

	/**
	 * Create an untrusted http symbol server
	 * @param url string url
	 * @return new {@link HttpSymbolServer} instance
	 */
	public static HttpSymbolServer createUntrusted(String url) {
		return new HttpSymbolServer(URI.create(url), false);
	}

	private final URI serverURI;
	private boolean trusted;

	/**
	 * Creates a new instance of a HttpSymbolServer.
	 * 
	 * @param serverURI URI / URL of the symbol server 
	 */
	public HttpSymbolServer(URI serverURI) {
		this(serverURI, false);
	}

	/**
	 * Creates a new instance of a HttpSymbolServer.
	 * 
	 * @param serverURI URI / URL of the symbol server 
	 * @param isTrusted flag, if true the http server can be trusted when querying and downloading
	 */
	public HttpSymbolServer(URI serverURI, boolean isTrusted) {
		String path = serverURI.getPath();
		this.serverURI =
			path.endsWith("/") ? serverURI : serverURI.resolve(serverURI.getPath() + "/");
		this.trusted = isTrusted;
	}

	@Override
	public String getName() {
		return (trusted ? "!" : "") + serverURI.toString();
	}

	@Override
	public String getDescriptiveName() {
		return serverURI.toString();
	}

	@Override
	public boolean isValid(TaskMonitor monitor) {
		// NOTE: checking a http symbolserver's state by testing the
		// existence of a file is not 100% universally correct, as different
		// webserver implementations will handle this differently, but
		// no better options are apparent.
		// Just getting any HTTP response, including a 404 not found, isn't a
		// good indication that the symbol server is valid as it could be
		// a missing subtree of a parent web site.
		return exists("", monitor) || exists(PINGME_FILENAME, monitor);
	}

	private HttpRequest.Builder request(String str) throws IOException {
		try {
			return HttpRequest.newBuilder(serverURI.resolve(str))
					.setHeader("User-Agent", GHIDRA_USER_AGENT);
		}
		catch (IllegalArgumentException e) {
			throw new IOException(e);
		}
	}

	@Override
	public boolean exists(String filename, TaskMonitor monitor) {
		try {
			HttpRequest request = request(filename)
					.timeout(Duration.ofMillis(HTTP_REQUEST_TIMEOUT_MS))
					.method("HEAD", BodyPublishers.noBody())
					.build();

			Msg.debug(this,
				logPrefix() + ": Checking exist for [" + filename + "]: " + request.toString());
			HttpResponse<Void> response =
				HttpClients.getHttpClient().send(request, BodyHandlers.discarding());
			int statusCode = response.statusCode();
			Msg.debug(this, logPrefix() + ": Response: " + response.statusCode());

			return statusCode == HTTP_STATUS_OK;
		}
		catch (InterruptedException | IOException e) {
			// ignore, return false
			return false;
		}
	}

	@Override
	public SymbolServerInputStream getFileStream(String filename, TaskMonitor monitor)
			throws IOException, CancelledException {
		monitor.setIndeterminate(true);
		monitor.setMessage("Connecting to " + serverURI);

		HttpRequest request = request(filename).GET().build();
		Msg.debug(this,
			logPrefix() + ": Getting file [" + filename + "]: " + request.toString());
		CompletableFuture<HttpResponse<InputStream>> futureResponse =
			HttpClients.getHttpClient().sendAsync(request, BodyHandlers.ofInputStream());
		CancelledListener l = () -> futureResponse.cancel(true);
		monitor.addCancelledListener(l);

		try {
			HttpResponse<InputStream> response =
				futureResponse.get(HTTP_REQUEST_TIMEOUT_MS, TimeUnit.MILLISECONDS);

			int statusCode = response.statusCode();
			monitor.setMessage(statusCode == HTTP_STATUS_OK ? "Success" : "Failed");
			Msg.debug(this, logPrefix() + ": Http response: " + response.statusCode());
			InputStream bodyIS = response.body();
			if (statusCode != HTTP_STATUS_OK) {
				// clean up the body inputstream since its just an error message
				uncheckedClose(bodyIS);
				throw new IOException("Unable to get file: " + statusCode);
			}
			long contentLen = response.headers().firstValueAsLong("Content-Length").orElse(-1);
			return new SymbolServerInputStream(bodyIS, contentLen);
		}
		catch (InterruptedException e) {
			throw new CancelledException("Download canceled");
		}
		catch (TimeoutException e) {
			throw new IOException("Connection timed out");
		}
		catch (ExecutionException e) {
			// if possible, unwrap the exception that happened inside the future
			Throwable cause = e.getCause();
			Msg.error(this, "Error during HTTP get", cause);
			throw (cause instanceof IOException)
					? (IOException) cause
					: new IOException("Error during HTTP get", cause);
		}
		finally {
			monitor.removeCancelledListener(l);
		}
	}

	@Override
	public String getFileLocation(String filename) {
		return serverURI.resolve(filename).toString();
	}

	@Override
	public boolean isTrusted() {
		return trusted;
	}

	@Override
	public void setTrusted(boolean isTrusted) {
		this.trusted = isTrusted;
	}

	@Override
	public String toString() {
		return String.format("HttpSymbolServer: [ url: %s, trusted: %b, storageLevel: %d]",
			serverURI.toString(), trusted, storageLevel);
	}

	private String logPrefix() {
		return getClass().getSimpleName() + "[" + serverURI + "]";
	}

	private static void uncheckedClose(InputStream is) {
		try {
			is.close();
		}
		catch (IOException e) {
			// ignore it
		}
	}

}
