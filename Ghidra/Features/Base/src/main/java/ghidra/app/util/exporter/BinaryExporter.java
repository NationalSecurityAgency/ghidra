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
package ghidra.app.util.exporter;

import java.io.*;
import java.util.List;

import ghidra.app.util.DomainObjectService;
import ghidra.app.util.Option;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.util.HelpLocation;
import ghidra.util.task.TaskMonitor;

/**
 * An implementation of exporter that creates
 * an Binary representation of the program.
 */
public class BinaryExporter extends Exporter {

	public BinaryExporter() {
		super("Binary", "bin", new HelpLocation("ExporterPlugin", "binary"));
	}

	@Override
	public boolean export(File file, DomainObject domainObj, AddressSetView addrSet,
			TaskMonitor monitor) throws IOException, ExporterException {

		if (!(domainObj instanceof Program)) {
			log.appendMsg("Unsupported type: " + domainObj.getClass().getName());
			return false;
		}
		Program program = (Program) domainObj;

		Memory memory = program.getMemory();

		if (addrSet == null) {
			addrSet = memory;
		}

		FileOutputStream fos = new FileOutputStream(file);

		AddressSet set = new AddressSet(addrSet);

		//skip blocks that are not initialized...
		MemoryBlock[] blocks = memory.getBlocks();
		for (int i = 0; i < blocks.length; ++i) {
			if (!blocks[i].isInitialized()) {
				set.delete(new AddressRangeImpl(blocks[i].getStart(), blocks[i].getEnd()));
			}
		}

		try {
			AddressRangeIterator iter = set.getAddressRanges();
			while (iter.hasNext()) {
				AddressRange range = iter.next();
				byte[] mem = new byte[(int) range.getLength()];
				int numBytes = memory.getBytes(range.getMinAddress(), mem);
				fos.write(mem, 0, numBytes);
			}
		}
		catch (MemoryAccessException e) {
			throw new ExporterException(e);
		}
		finally {
			fos.close();
		}

		return true;
	}

	@Override
	public List<Option> getOptions(DomainObjectService domainObjectService) {
		return EMPTY_OPTIONS;
	}

	@Override
	public void setOptions(List<Option> options) {
	}
}
