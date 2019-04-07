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
package ghidra.util.search;

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.junit.Test;

import ghidra.app.plugin.core.searchmem.RegExSearchData;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.datastruct.ListAccumulator;
import ghidra.util.search.memory.*;
import ghidra.util.task.TaskMonitor;

public class RegExMemSearcherTaskTest extends AbstractGhidraHeadlessIntegrationTest {

	private Program buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("TestX86", ProgramBuilder._X86);
		builder.createMemory(".text", Long.toHexString(0x1001000), 0x100);

		return builder.getProgram();
	}

	@Test
	public void testFindMatchesWithinMatches() throws Exception {

		Program p = buildProgram();
		String regex = "\\x00\\x00\\x00\\x00";
		RegExSearchData searchData = new RegExSearchData(regex);
		int max = 50;
		SearchInfo searchInfo = new SearchInfo(searchData, max, false, true, 1, false, null);
		AddressSetView addrs = p.getMemory().getLoadedAndInitializedAddressSet();

		RegExMemSearcherAlgorithm searcher =
			new RegExMemSearcherAlgorithm(searchInfo, addrs, p, true);

		ListAccumulator<MemSearchResult> accumulator = new ListAccumulator<>();
		searcher.search(accumulator, TaskMonitor.DUMMY);
		List<MemSearchResult> results = accumulator.asList();

		assertEquals(max, results.size());

		assertEquals(0x1001000, results.get(0).getAddress().getOffset());
		assertEquals(0x1001001, results.get(1).getAddress().getOffset());
		assertEquals(0x1001002, results.get(2).getAddress().getOffset());
	}

}
