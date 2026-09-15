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
package ghidra.app.util.bin.format.dwarf.external;

import java.io.IOException;
import java.io.InputStream;
import java.net.*;
import java.net.http.*;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.channels.UnresolvedAddressException;
import java.util.Objects;
import java.util.concurrent.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.net.HttpClients;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;

/**
 * Queries debuginfod REST servers for debug objects.
 */
public class HttpDebugInfoDProvider implements DebugStreamProvider {
	private static final String GHIDRA_USER_AGENT = "Ghidra_HttpDebugInfoDProvider_client";
	private static final int HTTP_STATUS_OK = HttpURLConnection.HTTP_OK;
	private static final int HTTP_STATUS_INTERNAL_ERROR = HttpURLConnection.HTTP_INTERNAL_ERROR;
	private static final int HTTP_STATUS_NOT_FOUND = HttpURLConnection.HTTP_NOT_FOUND;
	private static final int DEFAULT_HTTP_REQUEST_TIMEOUT_MS = 10 * 1000; // 10 seconds
	private static final int DEFAULT_MAX_RETRY_COUNT = 5;
	private static final Pattern HTTPPROVIDER_REGEX = Pattern.compile("(http(s)?://.*)");

	public static boolean matches(String name) {
		return HTTPPROVIDER_REGEX.matcher(name).matches();
	}

	public static HttpDebugInfoDProvider create(String name,
			DebugInfoProviderCreatorContext context) {
		Matcher m = HTTPPROVIDER_REGEX.matcher(name);
		if (!m.matches()) {
			return null;
		}
		String uriStr = m.group(1);
		URI serverURI = URI.create(uriStr);
		return new HttpDebugInfoDProvider(serverURI);
	}

	private final URI serverURI;
	private int retriedCount;
	private int notFoundCount;
	private int maxRetryCount = DEFAULT_MAX_RETRY_COUNT;
	private int httpRequestTimeoutMs = DEFAULT_HTTP_REQUEST_TIMEOUT_MS;

	/**
	 * Creates a new instance of a HttpSymbolServer.
	 * 
	 * @param serverURI URI / URL of the symbol server 
	 */
	public HttpDebugInfoDProvider(URI serverURI) {
		String path = serverURI.getPath();
		this.serverURI =
			path.endsWith("/") ? serverURI : serverURI.resolve(serverURI.getPath() + "/");
	}

	@Override
	public String getName() {
		return serverURI.toString();
	}

	@Override
	public String getDescriptiveName() {
		return serverURI.toString();
	}

	@Override
	public DebugInfoProviderStatus getStatus(TaskMonitor monitor) {
		return DebugInfoProviderStatus.UNKNOWN;
	}

	private HttpRequest.Builder request(ExternalDebugInfo id) throws IOException {
		try {
			String extra = "";
			if (id.getObjectType() == ObjectType.SOURCE) {
				extra = "/" + Objects.requireNonNullElse(id.getExtra(), "");
			}
			String requestPath = "buildid/%s/%s%s".formatted(id.getBuildId(),
				id.getObjectType().getPathString(), extra);
			return HttpRequest.newBuilder(serverURI.resolve(requestPath))
					.setHeader("User-Agent", GHIDRA_USER_AGENT);
		}
		catch (IllegalArgumentException e) {
			throw new IOException(e);
		}
	}

	@Override
	public StreamInfo getStream(ExternalDebugInfo id, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (!id.hasBuildId()) {
			return null;
		}

		monitor.setIndeterminate(true);
		monitor.setMessage("Connecting to " + serverURI);

		HttpRequest request = request(id).GET().build();

		retryLoop: for (int retryNum = 0; retryNum < maxRetryCount; retryNum++) {
			if (retryNum > 0) {
				Msg.debug(this, logPrefix() + ": retry count: " + retryNum);
				retriedCount++;
			}
			InputStream bodyIS = null;
			try {
				HttpResponse<InputStream> response = tryGet(request, monitor);
				int statusCode = response.statusCode();
				bodyIS = response.body();
				HttpHeaders headers = response.headers();
				Msg.debug(this, logPrefix() + ": Http response: " + response.statusCode());
				switch (statusCode) {
					case HTTP_STATUS_OK: {
						// TODO: typical response headers from debuginfod that we may want to make 
						// use of in the future:
						// x-debuginfod-size: 245872
						// x-debuginfod-archive: /path/to/somepackagefile.packagetype_ext
						// x-debuginfod-file: 1e1abd8faf1cb290df755a558377c5d7def3b1.debug
						long contentLen = headers.firstValueAsLong("Content-Length").orElse(-1);
						long size = headers.firstValueAsLong("x-debuginfod-size").orElse(-1);
						String archivePath = headers.firstValue("x-debuginfod-archive").orElse("");
						String debugFile = headers.firstValue("x-debuginfod-file").orElse("");
						Msg.debug(this,
							logPrefix() +
								": Debug object info size: %d, archive path: %s, debug file: %s"
										.formatted(size, archivePath, debugFile));
						Msg.info(this,
							"Found DWARF external debug file: %s".formatted(request.uri()));

						InputStream successIS = bodyIS;
						bodyIS = null;
						return new StreamInfo(successIS, contentLen);
					}
					case HTTP_STATUS_INTERNAL_ERROR:
						// retry connection
						continue retryLoop;
					case HTTP_STATUS_NOT_FOUND:
						notFoundCount++;
						return null;
					default:
						Msg.debug(this, logPrefix() + ": unexpected result status: " + statusCode);
						return null;
				}
			}
			catch (ConnectException e) {
				if (e.getCause() instanceof UnresolvedAddressException) {
					Msg.debug(this, logPrefix() + ": bad server name? " + serverURI);
					return null; // fail
				}
				// fall thru, retry
			}
			catch (TimeoutException e) {
				// fall thru, retry
			}
			finally {
				uncheckedClose(bodyIS);
			}
		}
		Msg.debug(this, logPrefix() + ": failed to query for: " + id);
		return null;
	}

	private HttpResponse<InputStream> tryGet(HttpRequest request, TaskMonitor monitor)
			throws IOException, CancelledException, TimeoutException {
		Msg.debug(this, logPrefix() + ": " + request.toString());
		CompletableFuture<HttpResponse<InputStream>> futureResponse =
			HttpClients.getHttpClient().sendAsync(request, BodyHandlers.ofInputStream());
		CancelledListener l = () -> futureResponse.cancel(true);
		monitor.addCancelledListener(l);

		try {
			HttpResponse<InputStream> response =
				futureResponse.get(httpRequestTimeoutMs, TimeUnit.MILLISECONDS);

			return response;
		}
		catch (InterruptedException e) {
			throw new CancelledException("Download canceled");
		}
		catch (ExecutionException e) {
			// if possible, unwrap the exception that happened inside the future
			Throwable cause = e.getCause();
			if (cause instanceof IOException ioe) {
				throw ioe;
			}
			Msg.error(this, "Error during HTTP get", cause);
			throw new IOException("Error during HTTP get", cause);
		}
		finally {
			monitor.removeCancelledListener(l);
		}
	}

	private String logPrefix() {
		return getClass().getSimpleName() + "[" + serverURI + "]";
	}

	private static void uncheckedClose(InputStream is) {
		try {
			if (is != null) {
				is.close();
			}
		}
		catch (IOException e) {
			// ignore it
		}
	}

	public int getNotFoundCount() {
		return notFoundCount;
	}

	public int getRetriedCount() {
		return retriedCount;
	}

	public void setMaxRetryCount(int maxRetryCount) {
		this.maxRetryCount = maxRetryCount;
	}

	public void setHttpRequestTimeoutMs(int httpRequestTimeoutMs) {
		this.httpRequestTimeoutMs = httpRequestTimeoutMs;
	}
}
