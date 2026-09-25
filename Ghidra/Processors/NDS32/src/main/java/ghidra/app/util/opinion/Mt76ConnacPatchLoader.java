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
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

/**
 * Loader for the MediaTek MT76 connac firmware patch image (mt7615/mt7663/mt7622).
 * The file is a 30-byte ASCII-ish header (build date, platform, version, checksum)
 * followed by a flat binary payload that is written directly to ILM_RAM at the
 * configured base address.  The newer connac2/3 format (mt7921 and later) uses
 * a section-descriptor table and is not handled here.
 */
public class Mt76ConnacPatchLoader extends AbstractProgramLoader {

	public static final String NAME = "MediaTek MT76 connac patch";

	/** Size of the {@code mt7615_patch_hdr} header in bytes. */
	public static final int PATCH_HDR_SIZE = 0x1e;

	/** Default {@code ILM_RAM} base address for the MT7663 BT core. */
	public static final long DEFAULT_LOAD_ADDR = 0xdc000L;

	private static final String OPTION_NAME_BASE_ADDR = "Patch load address";
	private static final String OPTION_NAME_BLOCK_NAME = "Patch block name";
	private static final String DEFAULT_BLOCK_NAME = "patch";

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 50;
	}

	@Override
	public boolean supportsLoadIntoProgram() {
		return true;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		if (!looksLikeMt76Patch(provider)) {
			return Collections.emptyList();
		}
		// MT7663 pspec defines ILM_ROM/ILM_RAM/DLM/csr with the right base addresses.
		LanguageCompilerSpecPair lcs = new LanguageCompilerSpecPair(
			"NDS32:LE:32:mt7663", "default");
		return List.of(new LoadSpec(this, DEFAULT_LOAD_ADDR, lcs, true));
	}

	// The mt76 patch format has no magic number; sniff via the printable-ASCII
	// build_date (must contain a newline) and platform fields in the header.
	private static boolean looksLikeMt76Patch(ByteProvider provider) throws IOException {
		if (provider.length() < 0x40) {
			return false;
		}
		byte[] hdr = provider.readBytes(0, PATCH_HDR_SIZE);
		int printable = 0;
		int newline = 0;
		for (int i = 0; i < 16; i++) {
			int b = hdr[i] & 0xff;
			if (b == 0x0a) {
				newline++;
			}
			else if (b >= 0x20 && b < 0x7f) {
				printable++;
			}
		}
		if (newline == 0 || (printable + newline) < 14) {
			return false;
		}
		for (int i = 16; i < 20; i++) {
			int b = hdr[i] & 0xff;
			if (b < 0x20 || b >= 0x7f) {
				return false;
			}
		}
		return true;
	}

	@Override
	protected List<Loaded<Program>> loadProgram(ImporterSettings settings)
			throws IOException, LoadException, CancelledException {
		Program prog = createProgram(settings);
		List<Loaded<Program>> loadedList = List.of(new Loaded<>(prog, settings));
		boolean success = false;
		try {
			// Default memory blocks must exist before loadInto so the payload
			// writes land in the language-defined ILM_RAM block.
			createDefaultMemoryBlocks(prog, settings);
			loadInto(prog, settings);
			success = true;
			return loadedList;
		}
		finally {
			if (!success) {
				loadedList.forEach(Loaded::close);
			}
		}
	}

	@Override
	protected void loadProgramInto(Program prog, ImporterSettings settings)
			throws IOException, LoadException, CancelledException {
		ByteProvider provider = settings.provider();

		long fileLen = provider.length();
		if (fileLen <= PATCH_HDR_SIZE) {
			throw new LoadException(
				"MT76 patch file is too short (need at least " + PATCH_HDR_SIZE + " bytes)");
		}
		long payloadLen = fileLen - PATCH_HDR_SIZE;

		Address baseAddr = getBaseAddress(settings.options(), prog);
		String blockName = getBlockName(settings.options());

		Msg.info(this, String.format(
			"%s: Loading %d-byte payload at %s (stripped %d-byte header)",
			getName(), payloadLen, baseAddr, PATCH_HDR_SIZE));

		Memory mem = prog.getMemory();
		try {
			MemoryBlock existing = mem.getBlock(baseAddr);
			// Address.subtract throws across address spaces -- check equality first.
			boolean covered = existing != null
				&& existing.getStart().getAddressSpace().equals(baseAddr.getAddressSpace())
				&& existing.getEnd().subtract(baseAddr) + 1 >= payloadLen;
			if (covered) {
				if (!existing.isInitialized()) {
					mem.convertToInitialized(existing, (byte) 0);
					existing = mem.getBlock(baseAddr);
				}
				try (InputStream in = provider.getInputStream(PATCH_HDR_SIZE)) {
					byte[] payload = in.readAllBytes();
					mem.setBytes(baseAddr, payload);
				}
				if (!existing.isExecute()) {
					existing.setExecute(true);
				}
				Msg.info(this, String.format(
					"%s: Wrote payload into existing block '%s'", getName(), existing.getName()));
			}
			else {
				try (InputStream in = provider.getInputStream(PATCH_HDR_SIZE)) {
					MemoryBlock newBlock = mem.createInitializedBlock(blockName, baseAddr,
						in, payloadLen, settings.monitor(), false);
					newBlock.setRead(true);
					newBlock.setWrite(true);
					newBlock.setExecute(true);
				}
				Msg.info(this, String.format(
					"%s: Created new block '%s' for patch payload", getName(), blockName));
			}
		}
		catch (Exception e) {
			throw new LoadException("Failed to load MT76 patch payload: " + e.getMessage());
		}

		// Schedule auto-analysis on the freshly-loaded patch region.
		// reAnalyzeAll() notifies byte/code/data analyzer task queues, so
		// the next startAnalysis (whether triggered by the headless driver,
		// by the GUI's post-import analyze step, or by a script) walks the
		// new region without the user having to invoke "Analyze Program"
		// again.  Scheduling here -- and not calling startAnalysis -- keeps
		// the loader composable with the rest of the import pipeline.
		AddressSet patchRange =
			new AddressSet(baseAddr, baseAddr.add(payloadLen - 1));
		AutoAnalysisManager.getAnalysisManager(prog).reAnalyzeAll(patchRange);
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		Address baseAddr = null;
		if (domainObject instanceof Program) {
			Program program = (Program) domainObject;
			AddressFactory af = program.getAddressFactory();
			if (af != null) {
				AddressSpace def = af.getDefaultAddressSpace();
				if (def != null) {
					baseAddr = def.getAddress(DEFAULT_LOAD_ADDR);
				}
			}
		}
		// Standalone import has no program yet -- derive the address from the
		// LoadSpec's language so the Option has a valid AddressFactory-bound
		// default (Options with a null default are rejected).
		if (baseAddr == null && loadSpec != null
			&& loadSpec.getLanguageCompilerSpec() != null) {
			try {
				AddressFactory af = DefaultLanguageService.getLanguageService()
					.getLanguage(loadSpec.getLanguageCompilerSpec().languageID)
					.getAddressFactory();
				baseAddr = af.getDefaultAddressSpace().getAddress(DEFAULT_LOAD_ADDR);
			}
			catch (Exception e) {
				// loadProgramInto will fall back to the program's default space
			}
		}
		List<Option> list = new ArrayList<>();
		list.add(Option.newAddress(OPTION_NAME_BASE_ADDR).value(baseAddr).build());
		list.add(Option.newString(OPTION_NAME_BLOCK_NAME).value(DEFAULT_BLOCK_NAME).build());
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		for (Option option : options) {
			String name = option.getName();
			if (name.equals(OPTION_NAME_BASE_ADDR)) {
				if (option.getValue() != null && !(option.getValue() instanceof Address)) {
					return OPTION_NAME_BASE_ADDR + " must be an Address";
				}
			}
			else if (name.equals(OPTION_NAME_BLOCK_NAME)) {
				if (option.getValue() != null
					&& !String.class.isAssignableFrom(option.getValueClass())) {
					return OPTION_NAME_BLOCK_NAME + " must be a String";
				}
			}
		}
		return null;
	}

	private Address getBaseAddress(List<Option> options, Program program) {
		for (Option option : options) {
			if (OPTION_NAME_BASE_ADDR.equals(option.getName())
				&& option.getValue() instanceof Address a) {
				return a;
			}
		}
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(DEFAULT_LOAD_ADDR);
	}

	private String getBlockName(List<Option> options) {
		for (Option option : options) {
			if (OPTION_NAME_BLOCK_NAME.equals(option.getName())
				&& option.getValue() instanceof String s && !s.isEmpty()) {
				return s;
			}
		}
		return DEFAULT_BLOCK_NAME;
	}
}
