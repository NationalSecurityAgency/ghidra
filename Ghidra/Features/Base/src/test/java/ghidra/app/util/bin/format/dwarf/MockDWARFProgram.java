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
package ghidra.app.util.bin.format.dwarf;

import java.io.IOException;

import ghidra.app.util.bin.format.dwarf.sectionprovider.DWARFSectionProvider;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class MockDWARFProgram extends DWARFProgram {

	public MockDWARFProgram(Program program, DWARFImportOptions importOptions,
			DWARFSectionProvider sectionProvider) throws IOException {
		super(program, importOptions, sectionProvider);
		this.dieContainer = new MockDIEContainer(this);
	}

	@Override
	public void init(TaskMonitor monitor) throws IOException {
		dieContainer.init(monitor);
		// dieContainer.indexData() is not called, data is added by caller manually
	}

	@Override
	public MockDIEContainer getDIEContainer() {
		return (MockDIEContainer) super.getDIEContainer();
	}

}
