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
package ghidra.app.util.opinion;

import java.io.File;
import java.io.IOException;
import java.util.*;

import generic.continues.GenericFactory;
import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.RandomAccessByteProvider;
import ghidra.app.util.bin.format.pe.*;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.MessageLogContinuesFactory;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Conv;
import ghidra.util.task.TaskMonitor;

/**
 * An opinion service for processing Microsoft DBG files.

 */
public class DbgLoader extends AbstractPeDebugLoader {

	/**
	 * DBG files are portable executable (PE) format files that contain debug
	 * information in Codeview format for the Visual Studio debugger (and
	 * possibly other formats, depending on how the DBG was created). When you
	 * do not have source for certain code, such libraries or Windows APIs, DBG
	 * files permit debugging. DBG files also permit you to do OLE RPC
	 * debugging. Microsoft Corporation. All rights reserved.
	 */
	public final static String DBG_NAME = "Debug Symbols (DBG)";
	private static final long MIN_BYTE_LENGTH = 46;

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		if (provider.length() < MIN_BYTE_LENGTH) {
			return loadSpecs;
		}
		SeparateDebugHeader debug =
			new SeparateDebugHeader(RethrowContinuesFactory.INSTANCE, provider);
		if (debug.getSignature() == SeparateDebugHeader.IMAGE_SEPARATE_DEBUG_SIGNATURE) {
			long imageBase = Conv.intToLong(debug.getImageBase());
			String machineName = debug.getMachineName();
			for (QueryResult result : QueryOpinionService.query(getName(), machineName, null)) {
				loadSpecs.add(new LoadSpec(this, imageBase, result));
			}
			if (loadSpecs.isEmpty()) {
				loadSpecs.add(new LoadSpec(this, imageBase, true));
			}
		}

		return loadSpecs;
	}

	@Override
	public void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program prog,
			TaskMonitor monitor, MessageLog log) throws IOException {

		GenericFactory factory = MessageLogContinuesFactory.create(log);

		if (!prog.getExecutableFormat().equals(PeLoader.PE_NAME)) {
			throw new IOException("Loading of DBG file may only be 'added' to existing " +
				PeLoader.PE_NAME + " Program");
		}

		SeparateDebugHeader debug = new SeparateDebugHeader(factory, provider);

		String parentPath = prog.getExecutablePath();
		File parentFile = new File(parentPath);

		RandomAccessByteProvider provider2 = null;
		try {
			provider2 = new RandomAccessByteProvider(parentFile);
			PortableExecutable parentPE =
				PortableExecutable.createPortableExecutable(factory, provider2, SectionLayout.FILE);
			Address imageBase = prog.getImageBase();
			Map<SectionHeader, Address> sectionToAddress = new HashMap<>();
			FileHeader fileHeader = parentPE.getNTHeader().getFileHeader();
			SectionHeader[] sectionHeaders = fileHeader.getSectionHeaders();
			for (SectionHeader sectionHeader : sectionHeaders) {
				sectionToAddress.put(sectionHeader,
					imageBase.add(sectionHeader.getVirtualAddress()));
			}
			processDebug(debug.getParser(), fileHeader, sectionToAddress, prog, monitor);
		}
		finally {
			if (provider2 != null) {
				provider2.close();
			}
		}
	}

	@Override
	public String getName() {
		return DBG_NAME;
	}

	@Override
	public boolean supportsLoadIntoProgram() {
		return true;
	}
}
