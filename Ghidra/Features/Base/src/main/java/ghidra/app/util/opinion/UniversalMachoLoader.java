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

import ghidra.app.util.Option;
import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.macho.MachException;
import ghidra.app.util.bin.format.ubi.FatHeader;
import ghidra.app.util.bin.format.ubi.UbiException;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for Mach-O files contained in a Universal Binary
 */
public class UniversalMachoLoader extends MachoLoader {

	public final static String UNIVERSAL_MACH_O_NAME = "Universal Mach-O";
	private static final long MIN_BYTE_LENGTH = 4;

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		// Efficient check to fail fast
		if (provider.length() < MIN_BYTE_LENGTH) {
			return loadSpecs;
		}

		// Efficient check to fail fast
		BinaryReader reader = new BinaryReader(provider, false);
		int magic = reader.readInt(0);
		if (magic != FatHeader.FAT_MAGIC && magic != FatHeader.FAT_CIGAM) {
			return loadSpecs;
		}

		// Only add the preferred load specs for each Mach-O so only 1 entry for each architecture
		// shows up.  Keep them all preferred though so the user is forced to pick one (headless
		// will just use the "first preferred" by default)
		for (ByteProvider wrapper : getWrappers(provider)) {
			super.findSupportedLoadSpecs(wrapper).stream()
					.filter(LoadSpec::isPreferred)
					.forEach(loadSpecs::add);
		}

		return loadSpecs;
	}

	@Override
	public void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log) throws IOException {
		for (ByteProvider wrapper : getWrappers(provider)) {
			for (LoadSpec ls : super.findSupportedLoadSpecs(wrapper)) {
				if (monitor.isCancelled()) {
					break;
				}
				if (loadSpec.getLanguageCompilerSpec().equals(ls.getLanguageCompilerSpec())) {
					super.load(wrapper, loadSpec, options, program, monitor, log);
					return;
				}
			}
		}
	}

	@Override
	public String getName() {
		return UNIVERSAL_MACH_O_NAME;
	}

	/**
	 * Gets a {@link List} of {@link ByteProviderWrapper}s, one for each entry in the Universal
	 * Binary
	 *  
	 * @param provider The Universal Binary's provider
	 * @return A {@link List} of {@link ByteProviderWrapper}s, one for each entry in the Universal
	 *   Binary
	 * @throws IOException if an IO-related error occurred
	 */
	private List<ByteProviderWrapper> getWrappers(ByteProvider provider) throws IOException {
		List<ByteProviderWrapper> wrappers = new ArrayList<>();
		try {
			FatHeader fatHeader = new FatHeader(provider);
			List<Long> machStarts = fatHeader.getMachStarts();
			List<Long> machSizes = fatHeader.getMachSizes();
			for (int i = 0; i < machStarts.size(); i++) {
				wrappers.add(new ByteProviderWrapper(provider, machStarts.get(i), machSizes.get(i),
					provider.getFSRL()));
			}
		}
		catch (MachException | UbiException e) {
			// not a problem, just don't add it
		}
		return wrappers;
	}

}
