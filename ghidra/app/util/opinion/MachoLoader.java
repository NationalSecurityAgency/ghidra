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

import java.io.IOException;
import java.util.*;

import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.macho.*;
import ghidra.app.util.bin.format.macho.prelink.PrelinkMap;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.listing.Program;
import ghidra.util.LittleEndianDataConverter;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for Mach-O files.
 */
public class MachoLoader extends AbstractLibrarySupportLoader {

	public final static String MACH_O_NAME = "Mac OS X Mach-O";
	private static final long MIN_BYTE_LENGTH = 4;

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		// Efficient check to fail fast
		if (provider.length() < MIN_BYTE_LENGTH) {
			return loadSpecs;
		}

		// Efficient check to fail fast
		byte[] magicBytes = provider.readBytes(0, 4);
		if (!MachConstants.isMagic(new LittleEndianDataConverter().getInt(magicBytes))) {
			return loadSpecs;
		}

		try {
			MachHeader machHeader =
				MachHeader.createMachHeader(RethrowContinuesFactory.INSTANCE, provider);
			String magic =
				CpuTypes.getMagicString(machHeader.getCpuType(), machHeader.getCpuSubType());
			List<QueryResult> results = QueryOpinionService.query(getName(), magic, null);
			for (QueryResult result : results) {
				loadSpecs.add(new LoadSpec(this, machHeader.getImageBase(), result));
			}
			if (loadSpecs.isEmpty()) {
				loadSpecs.add(new LoadSpec(this, machHeader.getImageBase(), true));
			}
		}
		catch (MachException e) {
			// not a problem, just don't add it
		}
		return loadSpecs;
	}

	@Override
	public void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, MemoryConflictHandler handler, TaskMonitor monitor, MessageLog log)
			throws IOException {

		try {
			// A Mach-O file may contain PRELINK information.  If so, we use a special
			// program builder that knows how to deal with it.
			List<PrelinkMap> prelinkList = MachoPrelinkUtils.parsePrelinkXml(provider, monitor);
			if (!prelinkList.isEmpty()) {
				MachoPrelinkProgramBuilder.buildProgram(program, provider, prelinkList, log, handler,
					monitor);
			}
			else {
				MachoProgramBuilder.buildProgram(program, provider, log, handler, monitor);
			}
		}
		catch (Exception e) {
			throw new IOException(e.getMessage());
		}
	}

	@Override
	public String getName() {
		return MACH_O_NAME;
	}
}
