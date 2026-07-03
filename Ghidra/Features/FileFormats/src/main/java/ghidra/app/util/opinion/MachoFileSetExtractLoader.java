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
import ghidra.file.formats.ios.fileset.MachoFileSetExtractor;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.listing.Group;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;

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
	public void load(Program program, ImporterSettings settings) throws IOException {

		try {
			FileBytes fileBytes =
				MemoryBlockUtils.createFileBytes(program, settings.provider(), settings.monitor());
			MachoExtractProgramBuilder.buildProgram(program, settings.provider(), fileBytes, false,
				settings.log(), settings.monitor());
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
	protected void loadProgramInto(Program program, ImporterSettings settings)
			throws IOException, LoadException, CancelledException {
		FSRL fsrl = settings.provider().getFSRL();
		Group[] children = program.getListing().getDefaultRootModule().getChildren();
		if (Arrays.stream(children).anyMatch(e -> e.getName().contains(fsrl.getPath()))) {
			settings.log().appendMsg("%s has already been added".formatted(fsrl.getPath()));
			return;
		}
		try {
			FileBytes fileBytes =
				MemoryBlockUtils.createFileBytes(program, settings.provider(), settings.monitor());
			MachoExtractProgramBuilder.buildProgram(program, settings.provider(), fileBytes, true,
				settings.log(), settings.monitor());
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
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		return List.of();
	}

	@Override
	protected boolean isLoadLibraries(ImporterSettings settings) {
		return false;
	}

	@Override
	protected boolean shouldSearchAllPaths(Program program, ImporterSettings settings) {
		return false;
	}

	@Override
	protected void postLoadProgramFixups(List<Loaded<Program>> loadedPrograms,
			ImporterSettings settings) throws CancelledException, IOException {
		// Do nothing
	}
}
