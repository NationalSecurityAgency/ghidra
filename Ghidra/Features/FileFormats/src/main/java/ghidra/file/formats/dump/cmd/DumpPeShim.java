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
		Object consumer = new Object();
		try {
			program.addConsumer(consumer);
			ImporterSettings settings = new ImporterSettings(provider, program.getName(), null,
				null, false, loadSpec, options, consumer, log, monitor);
			load(program, settings);
			monitor.checkCancelled();
		}
		finally {
			program.setEffectiveImageBase(null);
			program.release(consumer);
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

	@Override
	protected SectionLayout getSectionLayout() {
		return SectionLayout.MEMORY;
	}

	@Override
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

	@Override
	protected Map<SectionHeader, Address> processMemoryBlocks(PortableExecutable pe, Program prog,
			FileBytes fileBytes, TaskMonitor monitor, MessageLog log)
			throws AddressOverflowException, CancelledException {

		AddressFactory af = prog.getAddressFactory();
		AddressSpace space = af.getDefaultAddressSpace();
		Map<SectionHeader, Address> sectionToAddress = new HashMap<>();

		NTHeader ntHeader = pe.getNTHeader();
		FileHeader fileHeader = ntHeader.getFileHeader();
		OptionalHeader optionalHeader = ntHeader.getOptionalHeader();
		List<SectionHeader> sections = fileHeader.getSectionHeaders();

		// Header block
		int headerSize = (int) Math.min(getHeaderSize(pe, sections, space), fileBytes.getSize());
		Address imageBase = space.getAddress(optionalHeader.getImageBase());
		adjustBlock(imageBase, headerSize, HEADERS);

		// Section blocks
		monitor.setMessage("[" + prog.getName() + "]: processing sections...");
		if (sections.isEmpty()) {
			log.appendMsg("No sections found");
		}
		for (SectionHeader section : sections) {
			monitor.checkCancelled();

			Address addr = imageBase.add(section.getAlignedVirtualAddress(optionalHeader));

			String sectionName = section.getReadableName();
			int alignedRawSize = section.getAlignedSizeOfRawData(optionalHeader, log);
			int alignedVirtualSize = section.getAlignedVirtualSize(optionalHeader, log);

			if (section.getVirtualSize() == 0) {
				log.appendMsg("Section '%s' has size zero".formatted(sectionName));
			}

			if (section.getPointerToRawData() != 0 && alignedRawSize != 0) {
				sectionToAddress.put(section, addr);
				adjustBlock(addr, alignedVirtualSize, sectionName);
				alignedVirtualSize -= alignedRawSize;
				addr = addr.add(alignedRawSize);
			}

			if (alignedVirtualSize > 0) {
				adjustBlock(addr, alignedVirtualSize, sectionName);
				sectionToAddress.putIfAbsent(section, addr);
			}
		}

		return sectionToAddress;
	}

	@Override
	protected void addExternalReference(Data pointerData, ImportInfo importInfo, MessageLog log) {
		// Ignore
	}

}
