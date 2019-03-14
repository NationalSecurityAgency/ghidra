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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.*;
import ghidra.app.util.opinion.IntelHexRecord;
import ghidra.app.util.opinion.IntelHexRecordWriter;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.util.HelpLocation;
import ghidra.util.task.TaskMonitor;

public class IntelHexExporter extends Exporter {
	protected final static int MAX_BYTES_PER_LINE = 0x00000010;

	protected Option option;

	/**
	 * Constructs a new Intel Hex exporter.
	 */
	public IntelHexExporter() {
		this("Intel Hex", "hex", new HelpLocation("ExporterPlugin", "intel_hex"));
	}

	protected IntelHexExporter(String name, String extension, HelpLocation help) {
		super(name, extension, help);
	}

	@Override
	public List<Option> getOptions(DomainObjectService domainObjectService) {
		List<Option> optionsList = new ArrayList<>();

		DomainObject domainObject = domainObjectService.getDomainObject();
		if (!(domainObject instanceof Program)) {
			return null;
		}
		Program program = (Program) domainObject;

		option = new Option("Address Space", program.getAddressFactory().getDefaultAddressSpace());

		optionsList.add(option);
		return optionsList;
	}

	@Override
	public void setOptions(List<Option> options) throws OptionException {
		if (!options.isEmpty()) {
			option = options.get(0);
		}
	}

	@Override
	public boolean export(File file, DomainObject domainObj, AddressSetView addrSet,
			TaskMonitor monitor) throws IOException, ExporterException {

		log.clear();

		if (!(domainObj instanceof Program)) {
			log.appendMsg("Unsupported type: " + domainObj.getClass().getName());
			return false;
		}
		Program program = (Program) domainObj;
		if (program.getMaxAddress().getSize() > 32) {
			log.appendMsg("Cannot be used for programs larger than 32 bits");
			return false;
		}

		if (option == null) {
			getOptions(() -> program);
		}

		PrintWriter writer = new PrintWriter(new FileOutputStream(file));

		Memory memory = program.getMemory();

		if (addrSet == null) {
			addrSet = memory;
		}

		try {
			List<IntelHexRecord> records = dumpMemory(program, memory, addrSet, monitor);
			for (IntelHexRecord record : records) {
				writer.println(record.format());
			}
		}
		catch (MemoryAccessException e) {
			throw new ExporterException(e);
		}
		finally {
			// Close the PrintWriter
			//
			writer.close();

			option = null;
		}

		return true;
	}

	protected List<IntelHexRecord> dumpMemory(Program program, Memory memory,
			AddressSetView addrSetView, TaskMonitor monitor) throws MemoryAccessException {
		IntelHexRecordWriter writer = new IntelHexRecordWriter(MAX_BYTES_PER_LINE);

		AddressSet set = new AddressSet(addrSetView);

		MemoryBlock[] blocks = memory.getBlocks();
		for (int i = 0; i < blocks.length; ++i) {
			if (!blocks[i].isInitialized() ||
				blocks[i].getStart().getAddressSpace() != option.getValue()) {
				set.delete(new AddressRangeImpl(blocks[i].getStart(), blocks[i].getEnd()));
			}
		}

		AddressIterator addresses = set.getAddresses(true);
		while (addresses.hasNext()) {
			Address address = addresses.next();
			byte b = memory.getByte(address);
			writer.addByte(address, b);
		}

		Address entryPoint = null;
		AddressIterator entryPointIterator =
			program.getSymbolTable().getExternalEntryPointIterator();
		while (entryPoint == null && entryPointIterator.hasNext()) {
			Address address = entryPointIterator.next();
			if (set.contains(address)) {
				entryPoint = address;
			}
		}
		return writer.finish(entryPoint);
	}
}
