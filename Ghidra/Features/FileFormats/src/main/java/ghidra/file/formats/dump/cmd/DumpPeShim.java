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
package ghidra.file.formats.dump.cmd;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.pe.*;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.PeLoader;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.database.mem.MemoryMapDB;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class DumpPeShim extends PeLoader {

	private ProgramDB program;
	private ProgramFragment fragment;
	private ProgramModule rootModule;
	private ProgramModule module;

	public DumpPeShim(ProgramDB program) {
		this.program = program;
	}

	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program pgm, ProgramFragment frag, TaskMonitor monitor, MessageLog log)
			throws IOException, CancelledException {

		Collection<LoadSpec> loadSpecs = findSupportedLoadSpecs(provider);
		if (loadSpecs.isEmpty()) {
			Msg.error(this, "Not a valid PE image: " + frag.getName());
			return;
		}
		generateModule(pgm, frag);

		Address minAddress = module.getMinAddress();
		if (minAddress.getOffset() == 0) {
			Msg.warn(this, "Zero-based fragment - skipping");
			return;
		}
		program.setEffectiveImageBase(minAddress);
		try {
			load(provider, loadSpec, options, program, monitor, log);
			monitor.checkCancelled();
		}
		finally {
			program.setEffectiveImageBase(null);
		}

		shiftModule();
	}

	private void generateModule(Program pgm, ProgramFragment frag) {
		this.rootModule = pgm.getListing().getRootModule(0);
		this.fragment = frag;

		String name = fragment.getName();
		try {
			fragment.setName(name + "_pad");
			module = rootModule.createModule(name);
			module.reparent(name + "_pad", rootModule);
		}
		catch (DuplicateNameException e) {
			Msg.error(this, "Unable to convert " + name);
		}
		catch (NotFoundException e) {
			Msg.error(this, "Unable to reparent " + name);
		}
	}

	private void shiftModule() {
		try {
			module.moveChild(module.getName() + "_pad", module.getNumChildren() - 1);
		}
		catch (NotFoundException e) {
			Msg.error(this, "Unable to reparent " + module.getName());
		}
	}

	protected SectionLayout getSectionLayout() {
		return SectionLayout.MEMORY;
	}

	protected FileBytes createFileBytes(ByteProvider provider, Program pgm, TaskMonitor monitor)
			throws IOException, CancelledException {
		List<FileBytes> fileBytesList = pgm.getMemory().getAllFileBytes();
		return fileBytesList.get(0);
	}

	private void adjustBlock(Address address, long size, String name) {
		String fragmentName = module.getName() + "_" + name;
		try {
			MemoryMapDB memory = program.getMemory();
			if (memory.contains(address)) {
				ProgramFragment frag = module.createFragment(fragmentName);
				frag.move(address, address.add(size - 1));
			}
		}
		catch (NotFoundException e) {
			Msg.warn(this, "Fragment not in memory " + fragmentName);
		}
		catch (NullPointerException e) {
			Msg.error(this, "Unable to reparent " + fragmentName);
		}
		catch (DuplicateNameException e) {
			//Msg.warn(this, "Duplicate name exception: " + fragmentName);
		}
	}

	protected Map<SectionHeader, Address> processMemoryBlocks(PortableExecutable pe, Program prog,
			FileBytes fileBytes, TaskMonitor monitor, MessageLog log)
			throws AddressOverflowException {

		AddressFactory af = prog.getAddressFactory();
		AddressSpace space = af.getDefaultAddressSpace();
		Map<SectionHeader, Address> sectionToAddress = new HashMap<>();

		if (monitor.isCancelled()) {
			return sectionToAddress;
		}
		monitor.setMessage("[" + prog.getName() + "]: processing memory blocks...");

		NTHeader ntHeader = pe.getNTHeader();
		FileHeader fileHeader = ntHeader.getFileHeader();
		OptionalHeader optionalHeader = ntHeader.getOptionalHeader();

		SectionHeader[] sections = fileHeader.getSectionHeaders();
		if (sections.length == 0) {
			Msg.warn(this, "No sections found");
		}

		// Header block
		int virtualSize = (int) Math.min(getVirtualSize(pe, sections, space), fileBytes.getSize());
		long addr = optionalHeader.getImageBase();
		Address address = space.getAddress(addr);

		adjustBlock(address, virtualSize, HEADERS);

		// Section blocks
		try {
			for (int i = 0; i < sections.length; ++i) {
				if (monitor.isCancelled()) {
					return sectionToAddress;
				}

				addr = sections[i].getVirtualAddress() + optionalHeader.getImageBase();

				address = space.getAddress(addr);

				int rawDataSize = sections[i].getSizeOfRawData();
				int rawDataPtr = sections[i].getPointerToRawData();
				virtualSize = sections[i].getVirtualSize();
				if (rawDataSize != 0 && rawDataPtr != 0) {
					int dataSize =
						((rawDataSize > virtualSize && virtualSize > 0) || rawDataSize < 0)
								? virtualSize
								: rawDataSize;
					if (ntHeader.checkRVA(dataSize) ||
						(0 < dataSize && dataSize < pe.getFileLength())) {
						if (!ntHeader.checkRVA(dataSize)) {
							Msg.warn(this, "OptionalHeader.SizeOfImage < size of " +
								sections[i].getName() + " section");
						}
						String sectionName = sections[i].getReadableName();
						if (sectionName.isBlank()) {
							sectionName = "SECTION." + i;
						}
						sectionToAddress.put(sections[i], address);
						adjustBlock(address, virtualSize, sectionName);
					}
					if (rawDataSize == virtualSize) {
						continue;
					}
					else if (rawDataSize > virtualSize) {
						// virtual size fully initialized
						continue;
					}
					// remainder of virtual size is uninitialized
					if (rawDataSize < 0) {
						Msg.error(this,
							"Section[" + i + "] has invalid size " +
								Integer.toHexString(rawDataSize) + " (" +
								Integer.toHexString(virtualSize) + ")");
						break;
					}
					virtualSize -= rawDataSize;
					address = address.add(rawDataSize);
				}

				if (virtualSize == 0) {
					Msg.error(this, "Section[" + i + "] has size zero");
				}
				else {
					int dataSize = (virtualSize > 0 || rawDataSize < 0) ? virtualSize : 0;
					if (dataSize > 0) {
						sectionToAddress.put(sections[i], address);
						adjustBlock(address, virtualSize, sections[i].getReadableName());
					}
				}

			}
		}
		catch (IllegalStateException ise) {
			if (optionalHeader.getFileAlignment() != optionalHeader.getSectionAlignment()) {
				throw new IllegalStateException(ise);
			}
			Msg.warn(this, "Section header processing aborted");
		}

		return sectionToAddress;
	}

	@Override
	protected void addExternalReference(Data pointerData, ImportInfo importInfo, MessageLog log) {
		// Ignore
	}

}
