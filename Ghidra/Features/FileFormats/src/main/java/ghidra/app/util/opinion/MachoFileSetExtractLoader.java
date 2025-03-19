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

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.formats.ios.fileset.MachoFileSetExtractor;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for Mach-O file set entries extracted by Ghidra from a Mach-O file set
 */
public class MachoFileSetExtractLoader extends MachoLoader {

	public final static String MACHO_FILESET_EXTRACT_NAME = "Extracted Mach-O File Set Entry";

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		if (provider.length() >= MachoFileSetExtractor.FOOTER_V1.length) {
			if (Arrays.equals(MachoFileSetExtractor.FOOTER_V1,
				provider.readBytes(provider.length() - MachoFileSetExtractor.FOOTER_V1.length,
					MachoFileSetExtractor.FOOTER_V1.length))) {
				return super.findSupportedLoadSpecs(provider);
			}
		}
		return List.of();
	}

	@Override
	public void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log) throws IOException {

		try {
			FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);
			MachoExtractProgramBuilder.buildProgram(program, provider, fileBytes, log, monitor);
		}
		catch (CancelledException e) {
			return;
		}
		catch (IOException e) {
			throw e;
		}
		catch (Exception e) {
			throw new IOException(e);
		}
	}

	@Override
	protected void loadProgramInto(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			MessageLog messageLog, Program program, TaskMonitor monitor)
			throws IOException, LoadException, CancelledException {
		load(provider, loadSpec, options, program, monitor, messageLog);
	}

	@Override
	public boolean supportsLoadIntoProgram(Program program) {
		return MACHO_FILESET_EXTRACT_NAME.equals(program.getExecutableFormat());
	}

	@Override
	public String getName() {
		return MACHO_FILESET_EXTRACT_NAME;
	}

	@Override
	public int getTierPriority() {
		return 49; // Higher priority than MachoLoader
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram) {
		return List.of();
	}

	@Override
	protected boolean isLoadLibraries(List<Option> options) {
		return false;
	}

	@Override
	protected boolean shouldSearchAllPaths(Program program, List<Option> options) {
		return false;
	}

	@Override
	protected void postLoadProgramFixups(List<Loaded<Program>> loadedPrograms, Project project,
			LoadSpec loadSpec, List<Option> options, MessageLog messageLog, TaskMonitor monitor)
			throws CancelledException, IOException {
		// Do nothing
	}
}
