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

import static ghidra.test.MockHttpServerUtils.*;
import static java.net.HttpURLConnection.*;
import static java.util.stream.Collectors.*;
import static org.junit.Assert.*;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.*;

import org.junit.Test;

import com.sun.net.httpserver.HttpServer;

import generic.hash.HashUtilities;
import generic.test.AbstractGenericTest;
import ghidra.app.util.bin.format.dwarf.external.DebugStreamProvider.StreamInfo;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class HttpDebugInfoDProviderTest extends AbstractGenericTest {
	private TaskMonitor monitor = TaskMonitor.DUMMY;

	BuildIdDebugInfo id = new BuildIdDebugInfo(new byte[20] /* all 00's */);

	@Test
	public void testNoConnect() throws IOException, CancelledException {
		InetSocketAddress unusedAddr = nextLoopbackServerAddr();
		HttpDebugInfoDProvider httpProvider = new HttpDebugInfoDProvider(getURI(unusedAddr));
		StreamInfo stream = httpProvider.getStream(id, monitor);
		assertNull(stream);
	}

	@Test
	public void testGet() throws IOException, CancelledException {

		HttpServer server = createMockHttpServer();
		server.createContext("/buildid/" + id.getBuildIdHexString() + "/debuginfo",
			createStaticResponseHandler("application/octet-stream", "result1".getBytes()));
		server.createContext("/buildid/" + id.getBuildIdHexString() + "/executable",
			createStaticResponseHandler("application/octet-stream", "result2".getBytes()));
		server.createContext("/buildid/" + id.getBuildIdHexString() + "/source/usr/include/stdio.h",
			createStaticResponseHandler("application/octet-stream", "result3".getBytes()));

		HttpDebugInfoDProvider httpProvider =
			new HttpDebugInfoDProvider(getURI(server.getAddress()));
		try {
			server.start();

			assertStreamResult("result1", httpProvider.getStream(id, monitor));
			assertStreamResult("result2",
				httpProvider.getStream(id.withType(ObjectType.EXECUTABLE, null), monitor));
			assertStreamResult("result3", httpProvider
					.getStream(id.withType(ObjectType.SOURCE, "/usr/include/stdio.h"), monitor));

			assertEquals(0, httpProvider.getRetriedCount());
			assertEquals(0, httpProvider.getNotFoundCount());

		}
		finally {
			server.stop(0);
		}
	}

	@Test
	public void testExtraSourcePathTraversal() throws IOException, CancelledException {
		// ensure that the source file path is not modified ("..", etc) when used as URI

		List<URI> uriResults = new ArrayList<>();
		HttpServer server = createMockHttpServer();
		server.createContext("/buildid/", createRequestTrackingResponseHandler(
			"application/octet-stream", "result1".getBytes(), uriResults));

		HttpDebugInfoDProvider httpProvider =
			new HttpDebugInfoDProvider(getURI(server.getAddress()));
		try {
			server.start();

			assertStreamResult("result1", httpProvider.getStream(srcId("/path1"), monitor));
			assertStreamResult("result1", httpProvider.getStream(srcId("/../../path2"), monitor));
			assertStreamResult("result1",
				httpProvider.getStream(srcId("/path3///file.txt"), monitor));
		}
		finally {
			server.stop(0);
		}

		assertEquals(0, httpProvider.getRetriedCount());
		assertEquals(0, httpProvider.getNotFoundCount());

		Set<String> uriStrings = uriResults.stream().map(uri -> uri.toString()).collect(toSet());
		assertEquals(3, uriStrings.size());
		assertContainsSubstring("/path1", uriStrings);
		assertContainsSubstring("/../../path2", uriStrings);
		assertContainsSubstring("/path3///file.txt", uriStrings);
	}

	@Test
	public void testGetWithRetry() throws IOException, CancelledException {

		HttpServer server = createMockHttpServer();
		server.createContext("/buildid/" + id.getBuildIdHexString() + "/debuginfo",
			wrapHandlerWithRetryError(
				createStaticResponseHandler("application/octet-stream", "result1".getBytes()), 3,
				HTTP_INTERNAL_ERROR));

		HttpDebugInfoDProvider httpProvider =
			new HttpDebugInfoDProvider(getURI(server.getAddress()));
		try {
			server.start();

			assertStreamResult("result1", httpProvider.getStream(id, monitor));
			assertEquals(3, httpProvider.getRetriedCount());
		}
		finally {
			server.stop(0);
		}
	}

	@Test
	public void testTimeout() throws IOException, CancelledException {

		HttpServer server = createMockHttpServer();
		server.createContext("/buildid/" + id.getBuildIdHexString() + "/debuginfo", wrapHandlerWithDelay(
			createStaticResponseHandler("application/octet-stream", "result1".getBytes()), 3000));

		HttpDebugInfoDProvider httpProvider =
			new HttpDebugInfoDProvider(getURI(server.getAddress()));
		httpProvider.setMaxRetryCount(1);
		httpProvider.setHttpRequestTimeoutMs(1000);
		try {
			server.start();

			long startms = System.currentTimeMillis();
			assertNull(httpProvider.getStream(id, monitor));
			long elapsed = System.currentTimeMillis() - startms;
			assertTrue("Request took too long", elapsed < (1000 * 2)); // make sure request time was approx same as timeout setting
		}
		finally {
			server.stop(0);
		}
	}

	@Test
	public void testGetNotFound() throws IOException, CancelledException {

		HttpServer server = createMockHttpServer();

		HttpDebugInfoDProvider httpProvider =
			new HttpDebugInfoDProvider(getURI(server.getAddress()));
		try {
			server.start();

			assertNull(httpProvider.getStream(id, monitor));
			assertEquals(0, httpProvider.getRetriedCount());
			assertEquals(1, httpProvider.getNotFoundCount());
		}
		finally {
			server.stop(0);
		}
	}

	@Test
	public void testServerError() throws IOException, CancelledException {

		HttpServer server = createMockHttpServer();
		server.createContext("/buildid/" + id.getBuildIdHexString() + "/debuginfo",
			createStaticResponseHandler(HTTP_INTERNAL_ERROR, "text/plain", "".getBytes()));

		HttpDebugInfoDProvider httpProvider =
			new HttpDebugInfoDProvider(getURI(server.getAddress()));
		try {
			server.start();

			assertNull(httpProvider.getStream(id, monitor));
			assertEquals(4, httpProvider.getRetriedCount());
			assertEquals(0, httpProvider.getNotFoundCount());
		}
		finally {
			server.stop(0);
		}
	}

	//@Test
	public void testElfUtilsOrg() throws IOException, CancelledException {
		// test actual file from elfutils.org.
		// Not enabled by default
		// The specified buildId may stop being present at some point of time in the future 
		HttpDebugInfoDProvider httpProvider =
			new HttpDebugInfoDProvider(URI.create("https://debuginfod.elfutils.org/"));
		BuildIdDebugInfo eu_id = new BuildIdDebugInfo(
			NumericUtilities.convertStringToBytes("421e1abd8faf1cb290df755a558377c5d7def3b1"));
		assertStreamHash("f5894783abae9084e531b8da76bbb2444a688d18",
			httpProvider.getStream(eu_id, monitor));
	}

	private void assertStreamResult(String expectedResult, StreamInfo stream) throws IOException {
		try (stream) {
			String result = new String(stream.is().readAllBytes());
			assertEquals(expectedResult, result);
		}
	}

	private void assertStreamHash(String expectedHash, StreamInfo stream) throws IOException {
		try (stream) {
			String hash = HashUtilities.getHash("SHA1", stream.is());
			assertEquals(expectedHash, hash);
		}
	}

	private void assertContainsSubstring(String expectedSubstring, Collection<String> strings) {
		for (String s : strings) {
			if (s.contains(expectedSubstring)) {
				return;
			}
		}
		fail("Did not contain expected substring: " + expectedSubstring + ", " + strings);
	}

	private BuildIdDebugInfo srcId(String srcPath) {
		return new BuildIdDebugInfo(new byte[20], ObjectType.SOURCE, srcPath);
	}

}
