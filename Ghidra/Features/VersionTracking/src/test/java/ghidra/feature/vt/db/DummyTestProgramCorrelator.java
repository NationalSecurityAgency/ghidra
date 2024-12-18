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
package ghidra.feature.vt.db;

import static ghidra.feature.vt.db.VTTestUtils.*;

import ghidra.feature.vt.api.main.VTMatchSet;
import ghidra.feature.vt.api.util.VTAbstractProgramCorrelator;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class DummyTestProgramCorrelator extends VTAbstractProgramCorrelator {

	private String name = "DummyTestProgramCorrelator";
	private int matchCount = 1;

	public DummyTestProgramCorrelator() {
		this(1);
	}

	public DummyTestProgramCorrelator(Program sourceProgram, AddressSetView sourceAddressSet,
			Program destinationProgram, AddressSetView destinationAddressSet, ToolOptions options) {
		super(sourceProgram, sourceAddressSet, destinationProgram, destinationAddressSet, options);
	}

	public DummyTestProgramCorrelator(Program sourceProgram, Program destinationProgram) {
		super(sourceProgram, createAddressSet(), destinationProgram, createAddressSet(),
			createOptions());
	}

	public DummyTestProgramCorrelator(int matchCount) {
		super(null, createAddressSet(), null, createAddressSet(), createOptions());
		this.matchCount = matchCount;
	}

	private static AddressSet createAddressSet() {
		AddressSet as = new AddressSet();
		as.add(getRandomAddressRange());
		as.add(getRandomAddressRange());
		as.add(getRandomAddressRange());
		return as;
	}

	private static AddressRange getRandomAddressRange() {
		Address addr1 = addr();
		Address addr2 = addr();
		return new AddressRangeImpl(min(addr1, addr2), max(addr1, addr2));
	}

	private static Address min(Address addr1, Address addr2) {
		return addr1.compareTo(addr2) <= 0 ? addr1 : addr2;
	}

	private static Address max(Address addr1, Address addr2) {
		return addr1.compareTo(addr2) >= 0 ? addr1 : addr2;
	}

	private static ToolOptions createOptions() {
		ToolOptions newOptions = new ToolOptions("Non Empty Test Options");
		newOptions.setString("foo", getRandomString());

		return newOptions;
	}

	@Override
	public void doCorrelate(VTMatchSet matchSet, TaskMonitor monitor) throws CancelledException {
		for (int i = 0; i < matchCount; i++) {
			matchSet.addMatch(createRandomMatch(null));
		}
	}

	public void setName(String name) {
		this.name = name;
	}

	@Override
	public String getName() {
		return name;
	}
}
