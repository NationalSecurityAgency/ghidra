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
package sarif.export.mm;

import java.io.IOException;
import java.io.Writer;
import java.util.List;

import generic.stl.Pair;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import sarif.export.AbstractExtWriter;
import sarif.export.SarifObject;
import sarif.managers.MemoryMapBytesFile;
import sarif.managers.MemoryMapSarifMgr;

public class SarifMemoryMapWriter extends AbstractExtWriter {

	private List<Pair<AddressRange, MemoryBlock>> memory;
	private MemoryMapBytesFile bytesFile;
	private boolean write;

	public SarifMemoryMapWriter(List<Pair<AddressRange, MemoryBlock>> request, Writer baseWriter,
			MemoryMapBytesFile bytes, boolean isWriteContents) throws IOException {
		super(baseWriter);
		this.memory = request;
		this.bytesFile = bytes;
		this.write = isWriteContents;
	}

	@Override
	protected void genRoot(TaskMonitor monitor) throws CancelledException, IOException {
		genMaps(monitor);
		root.add("memory", objects);
	}

	private void genMaps(TaskMonitor monitor) throws CancelledException, IOException {
		monitor.initialize(memory.size());
		for (Pair<AddressRange, MemoryBlock> m : memory) {
			AddressRange range = m.first;
			ExtMemoryMap isf = new ExtMemoryMap(m.first, m.second, bytesFile, write);
			SarifObject sarif = new SarifObject(MemoryMapSarifMgr.SUBKEY, MemoryMapSarifMgr.KEY, getTree(isf),
					range.getMinAddress(), range.getMaxAddress());
			objects.add(getTree(sarif));
			monitor.increment();
		}
	}

}
