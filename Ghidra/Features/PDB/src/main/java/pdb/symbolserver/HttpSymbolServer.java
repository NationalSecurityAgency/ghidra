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

import ghidra.net.HttpClients;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link SymbolServer} that is accessed via HTTP.
 * <p>
 * 
 */
public class HttpSymbolServer extends AbstractSymbolServer {
	private static final String GHIDRA_USER_AGENT = "Ghidra_HttpSymbolServer_client";
	private static final int HTTP_STATUS_OK = HttpURLConnection.HTTP_OK;
	private static final int HTTP_REQUEST_TIMEOUT_MS = 10 * 1000; // 10 seconds
	
	/**
	 * Predicate that tests if the location string is an instance of a HttpSymbolServer location.
	 * 
	 * @param locationString symbol server location string
	 * @return boolean true if the string should be handled by the HttpSymbolServer class 
	 */
	public static boolean isHttpSymbolServerLocation(String locationString) {
		return locationString.startsWith("http://") || locationString.startsWith("https://");
	}
	
	private final URI serverURI;

	/**
	 * Creates a new instance of a HttpSymbolServer.
	 * 
	 * @param serverURI URI / URL of the symbol server 
	 */
	public HttpSymbolServer(URI serverURI) {
		String path = serverURI.getPath();
		this.serverURI =
			path.endsWith("/") ? serverURI : serverURI.resolve(serverURI.getPath() + "/");
	}

	@Override
	public String getName() {
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

	private HttpRequest.Builder request(String str) {
		return HttpRequest.newBuilder(serverURI.resolve(str))
				.setHeader("User-Agent", GHIDRA_USER_AGENT);
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
	public boolean isLocal() {
		return false;
	}

	@Override
	public String toString() {
		return String.format("HttpSymbolServer: [ url: %s, storageLevel: %d]", serverURI.toString(),
			storageLevel);
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
