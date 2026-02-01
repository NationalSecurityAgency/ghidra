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

import static ghidra.test.MockHttpServerUtils.*;
import static org.junit.Assert.*;

import java.io.IOException;
import java.net.URI;
import java.util.List;

import org.junit.Test;

import com.sun.net.httpserver.HttpServer;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class HttpSymbolServerTest {

	private TaskMonitor monitor = TaskMonitor.DUMMY;

	//@Test
	public void testMSFTSymbolServer() {
		// This test is not enabled by default as it depends on an third-party resource
		HttpSymbolServer httpSymbolServer =
			new HttpSymbolServer(URI.create("http://msdl.microsoft.com/download/symbols/"));
		SymbolFileInfo pdbInfo =
			SymbolFileInfo.fromValues("kernelbase.pdb", "C1C44EDD93E1B8BA671874B5C1490C2D", 1);

		List<SymbolFileLocation> results =
			httpSymbolServer.find(pdbInfo, FindOption.NO_OPTIONS, TaskMonitor.DUMMY);
		assertEquals(1, results.size());
	}

	@Test
	public void testLocalHttpserverLevel1() throws IOException, CancelledException {
		HttpServer server = createMockHttpServer();

		server.createContext("/kernelbase.pdb/C1C44EDD93E1B8BA671874B5C1490C2D1/kernelbase.pdb",
			createStaticResponseHandler("application/octet", "result1".getBytes()));

		try {
			server.start();

			HttpSymbolServer httpSymbolServer = new HttpSymbolServer(getURI(server.getAddress()));
			SymbolFileInfo pdbInfo =
				SymbolFileInfo.fromValues("kernelbase.pdb", "C1C44EDD93E1B8BA671874B5C1490C2D", 1);
			List<SymbolFileLocation> results =
				httpSymbolServer.find(pdbInfo, FindOption.NO_OPTIONS, monitor);
			assertEquals(1, results.size());
			SymbolFileLocation result = results.get(0);

			SymbolServerInputStream stream =
				httpSymbolServer.getFileStream(result.getPath(), monitor);
			assertStreamResult("result1", stream);
		}
		finally {
			server.stop(0);
		}
	}

	@Test
	public void testLocalHttpserverLevel2() throws IOException, CancelledException {
		HttpServer server = createMockHttpServer();
		server.createContext("/index2.txt",
			createStaticResponseHandler("text/plain", "".getBytes()));

		server.createContext("/ke/kernelbase.pdb/C1C44EDD93E1B8BA671874B5C1490C2D1/kernelbase.pdb",
			createStaticResponseHandler("application/octet", "result1".getBytes()));

		try {
			server.start();

			HttpSymbolServer httpSymbolServer = new HttpSymbolServer(getURI(server.getAddress()));
			SymbolFileInfo pdbInfo =
				SymbolFileInfo.fromValues("kernelbase.pdb", "C1C44EDD93E1B8BA671874B5C1490C2D", 1);
			List<SymbolFileLocation> results =
				httpSymbolServer.find(pdbInfo, FindOption.NO_OPTIONS, monitor);
			assertEquals(1, results.size());
			SymbolFileLocation result = results.get(0);

			SymbolServerInputStream stream =
				httpSymbolServer.getFileStream(result.getPath(), monitor);
			assertStreamResult("result1", stream);
		}
		finally {
			server.stop(0);
		}
	}

	private void assertStreamResult(String expectedResult, SymbolServerInputStream stream)
			throws IOException {
		try (stream) {
			String result = new String(stream.getInputStream().readAllBytes());
			assertEquals(expectedResult, result);
		}
	}

}
