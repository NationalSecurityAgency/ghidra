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
package ghidra.app.util.bin.format.golang.rtti;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.util.bin.format.golang.GoVer;
import ghidra.app.util.bin.format.golang.rtti.GoApiSnapshot.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GoApiSnapshotTest extends AbstractGenericTest {

	@Test
	public void testSnapshotsExistForAllSupportedMinorVers() throws IOException {
		for (GoVer goMinorVer : GoRttiMapper.SUPPORTED_VERSIONS.asList()) {
			File jsonFile = GoApiSnapshot.getApiSnapshotFile(goMinorVer, "", "");
			assertTrue(jsonFile.exists());
		}
	}

	@Test
	public void testWellKnownSymbolsInEachSnapshot() throws IOException, CancelledException {
		for (GoVer goMinorVer : GoRttiMapper.SUPPORTED_VERSIONS.asList()) {
			GoApiSnapshot gas = GoApiSnapshot.get(goMinorVer, "amd64", "linux", TaskMonitor.DUMMY);
			GoTypeDef runtimeType = gas.getTypeDef("runtime._type");
			assertNotNull(runtimeType);
			assertTrue(runtimeType instanceof GoStructDef || runtimeType instanceof GoAliasDef);
		}

	}

}
