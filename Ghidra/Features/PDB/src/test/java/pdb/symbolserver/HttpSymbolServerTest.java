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

import static org.junit.Assert.*;

import java.net.URI;
import java.util.List;

import ghidra.util.task.TaskMonitor;

public class HttpSymbolServerTest {

	//@Test
	public void test() {
		// This test is not enabled by default as it depends on an third-party resource
		HttpSymbolServer httpSymbolServer =
			new HttpSymbolServer(URI.create("http://msdl.microsoft.com/download/symbols/"));
		SymbolFileInfo pdbInfo =
			SymbolFileInfo.fromValues("kernelbase.pdb", "C1C44EDD93E1B8BA671874B5C1490C2D", 1);

		List<SymbolFileLocation> results =
			httpSymbolServer.find(pdbInfo, FindOption.NO_OPTIONS, TaskMonitor.DUMMY);
		assertEquals(1, results.size());
	}

}
