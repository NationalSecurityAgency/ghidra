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
package ghidra.app.plugin.core.analysis;

import static org.junit.Assert.*;

import java.io.File;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.app.util.opinion.Loaded;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.app.util.opinion.Mt76ConnacPatchLoader;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;

/**
 * Demonstrates and exercises the full MediaTek MT7663 BT firmware
 * load flow.  Four stages are walked, each followed by an assertion
 * that the program's state has changed in the expected way:
 *
 * <ol>
 * <li><b>ROM</b> -- Create the default memory blocks declared by the
 *     {@code NDS32:LE:32:mt7663} processor spec ({@code ILM_ROM},
 *     {@code ILM_RAM}, {@code DLM}) and write the mask-ROM image
 *     bytes into {@code ILM_ROM}.  This is the equivalent of using
 *     Ghidra's {@code BinaryLoader} with the MT7663 language at base
 *     0x00000000.</li>
 *
 * <li><b>Auto-analyze ROM</b> -- Schedule and run the full default
 *     analyzer chain across the program (the same chain
 *     {@code analyzeHeadless} runs after {@code -import}).  Vector
 *     table analyzer labels the reset, disassembly walks from there,
 *     and the NDS32 analyzers ({@code NDS32Analyzer},
 *     {@code NDS32IFCAnalyzer}, {@code NDS32ITBAnalyzer}) populate
 *     functions, GP refs, IFC inline-body maps, and ex9.it
 *     annotations.  Data init below assumes the ROM is in this
 *     analyzed state.</li>
 *
 * <li><b>Data init</b> -- Run {@link NDS32DataInitAnalyzer}, which
 *     emulates the CRT from the reset vector and applies its memory
 *     writes (.data copy, .bss zero, MMIO scratch) to currently-
 *     uninitialized blocks.  Without this step, RW segments that the
 *     ROM boot code populates at runtime would still read as
 *     uninitialized and analysis would miss constants stored there.
 *     This analyzer is {@code setDefaultEnablement(false)} so it does
 *     not run on its own during auto-analysis -- it has to be turned
 *     on explicitly.</li>
 *
 * <li><b>Patch (firmware)</b> -- Use
 *     {@link Mt76ConnacPatchLoader#loadInto(Program, Loader.ImporterSettings)}
 *     to drop the firmware patch payload into {@code ILM_RAM} at
 *     {@code 0xdc000}.  The 30-byte mt76 patch header is stripped
 *     by the loader; the remaining flat binary is written directly
 *     into RAM as executable code.  The loader schedules analysis
 *     on the new region; running {@code startAnalysis} again picks
 *     it up and walks the patch.</li>
 * </ol>
 *
 * <p>Test fixtures (committed under
 * {@code Ghidra/Processors/NDS32/src/test.slow/resources/firmware/}):
 * <ul>
 * <li>{@code mt7663_00000000.bin} -- the MT7663 mask-ROM image.</li>
 * <li>{@code mt7663_patch_e2_hdr.bin} -- a connac patch image
 *     ({@code mt7615_patch_hdr} format) targeting MT7663 BT.</li>
 * </ul>
 */
public class NDS32MT7663LoadFlowTest extends AbstractGhidraHeadlessIntegrationTest {

	private static final String LANGUAGE = "NDS32:LE:32:mt7663";

	// Mt76ConnacPatchLoader.DEFAULT_LOAD_ADDR mirrors ILM_RAM_START.
	private static final long PATCH_LOAD_ADDR = 0x000dc000L;
	private static final int PATCH_HDR_SIZE = 0x1e;

	private TestEnv env;
	private Program program;

	private byte[] romBytes;
	private byte[] patchBytes;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		romBytes = readResource("/firmware/mt7663_00000000.bin");
		patchBytes = readResource("/firmware/mt7663_patch_e2_hdr.bin");
		assertTrue("ROM resource should be present (~900 KiB)",
			romBytes.length > 100_000);
		assertTrue("patch resource should be present (~270 KiB)",
			patchBytes.length > 100_000);
	}

	@After
	public void tearDown() throws Exception {
		if (program != null) {
			program.release(this);
			program = null;
		}
		if (env != null) {
			env.dispose();
		}
	}

	@Test
	public void loadFlow_romThenDataInitThenPatch() throws Exception {
		// ===== Stage 1: ROM =====
		loadRom();

		Memory mem = program.getMemory();
		MemoryBlock ilmRom = mem.getBlock("ILM_ROM");
		MemoryBlock ilmRam = mem.getBlock("ILM_RAM");
		MemoryBlock dlm = mem.getBlock("DLM");
		assertNotNull("ILM_ROM block must exist after ROM load", ilmRom);
		assertNotNull("ILM_RAM block must exist after ROM load", ilmRam);
		assertNotNull("DLM block must exist after ROM load", dlm);
		assertTrue("ILM_ROM must be initialized", ilmRom.isInitialized());
		assertFalse("ILM_RAM must start uninitialized",
			ilmRam.isInitialized());
		assertFalse("DLM must start uninitialized", dlm.isInitialized());

		assertTrue("ILM_ROM must be readable", ilmRom.isRead());
		assertTrue("ILM_ROM must be executable", ilmRom.isExecute());
		assertTrue("ILM_RAM must be readable", ilmRam.isRead());
		assertTrue("ILM_RAM must be writable", ilmRam.isWrite());
		assertTrue("ILM_RAM must be executable", ilmRam.isExecute());
		assertTrue("DLM must be readable", dlm.isRead());
		assertTrue("DLM must be writable", dlm.isWrite());

		// The pspec also declares a `csr` block in the csreg space and a
		// table of CSR alias symbols under <default_symbols> (psw, ipsw,
		// ivb, ...).  Importing via BinaryLoader runs the same
		// applyProcessorLabels pass the GUI/headless import does, so
		// these end up in the symbol table -- if they do not, mfsr/mtsr
		// references in the disassembly listing render as bare hex
		// instead of by their conventional CSR names.
		MemoryBlock csr = mem.getBlock("csr");
		assertNotNull("csr block must exist after ROM load", csr);
		var symbols = program.getSymbolTable();
		for (String name : new String[] { "psw", "ipsw", "ivb", "itype",
			"eva", "ipc", "cpu_ver" }) {
			assertTrue("CSR alias symbol '" + name + "' must be present",
				symbols.getSymbols(name).hasNext());
		}
		assertTrue("DLM must be executable", dlm.isExecute());

		// Spot-check: the first 4 bytes of the ROM image are present in
		// ILM_ROM at offset 0.
		byte[] firstFour = new byte[4];
		mem.getBytes(addr(0x0), firstFour);
		assertArrayEquals("ILM_ROM[0..3] must match ROM bytes",
			java.util.Arrays.copyOfRange(romBytes, 0, 4), firstFour);

		// ===== Stage 2: auto-analyze ROM =====
		// Mirror the analyzeHeadless post-import step: schedule and run
		// the full default analyzer chain across the program.  This is
		// where NDS32VectorTableAnalyzer creates the `_start` label,
		// disassembly walks from the reset vector, and NDS32Analyzer /
		// NDS32IFCAnalyzer / NDS32ITBAnalyzer populate the program with
		// functions, GP refs, ex9.it annotations, etc.  The data-init
		// step that follows assumes the ROM is in this analyzed state.
		assertEquals("no functions should exist before auto-analysis",
			0, program.getFunctionManager().getFunctionCount());
		int analyzeRomTx = program.startTransaction("auto-analyze-rom");
		try {
			AutoAnalysisManager mgr =
				AutoAnalysisManager.getAnalysisManager(program);
			mgr.reAnalyzeAll(program.getMemory());
			mgr.startAnalysis(TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(analyzeRomTx, true);
		}
		int romFunctionCount = program.getFunctionManager().getFunctionCount();
		assertTrue("ROM auto-analysis should discover functions (got " +
			romFunctionCount + ")", romFunctionCount > 100);

		// The ROM contains its own mtusr,itb writer, so the ITB analyzer
		// should have elected an ITB value from a ROM-resident writer.
		BigInteger romItb = readItb();
		assertNotNull(
			"ROM auto-analysis should elect a (ROM-resident) ITB value",
			romItb);

		// ===== Stage 3: data init =====
		// Opt-in analyzer.  Reset vector for the MT7663 core sits
		// at 0x00000000 (the start of ILM_ROM).  No "Reset" symbol is
		// defined in the pspec, so set the explicit option.
		int initializedBlocksBefore = countInitializedBlocks(mem);

		int tx = program.startTransaction("data-init");
		try {
			Options opts = program.getOptions(Program.ANALYSIS_PROPERTIES);
			opts.setString(
				"NDS32 Data Init Trace.Reset vector address (hex, blank = symbol)",
				"0x00000000");
			new NDS32DataInitAnalyzer().added(program, mem, TaskMonitor.DUMMY,
				new MessageLog());
		}
		finally {
			program.endTransaction(tx, true);
		}

		// Data init either initializes a (sub-)block by copying
		// .data from ROM, or expands existing blocks.  Confirm SOME
		// post-init memory state changed -- either a new initialized
		// block exists, or one of the previously-uninitialized blocks
		// is now partially initialized.
		int initializedBlocksAfter = countInitializedBlocks(mem);
		assertTrue(
			"Data init should have promoted some memory to initialized " +
				"(before=" + initializedBlocksBefore +
				" after=" + initializedBlocksAfter + ")",
			initializedBlocksAfter > initializedBlocksBefore);

		// ===== Stage 4: patch (firmware) =====
		// Track the function count delta for the assertion below: the
		// patch payload should add functions on top of what ROM
		// analysis already discovered.
		int preLoadFunctionCount =
			program.getFunctionManager().getFunctionCount();
		loadPatch();

		MemoryBlock patchRegion = mem.getBlock(addr(PATCH_LOAD_ADDR));
		assertNotNull("Patch region must exist after loadInto",
			patchRegion);
		assertTrue("Patch region must be initialized after loadInto",
			patchRegion.isInitialized());
		assertTrue("Patch region must be executable after loadInto",
			patchRegion.isExecute());

		// Spot-check: the first 4 bytes of the patch payload (i.e.,
		// patchBytes[PATCH_HDR_SIZE..PATCH_HDR_SIZE+4]) are written
		// at PATCH_LOAD_ADDR.
		byte[] firstPayload = new byte[4];
		mem.getBytes(addr(PATCH_LOAD_ADDR), firstPayload);
		assertArrayEquals("First 4 bytes at patch load addr must match the " +
			"post-header payload of the patch file",
			java.util.Arrays.copyOfRange(patchBytes, PATCH_HDR_SIZE,
				PATCH_HDR_SIZE + 4),
			firstPayload);

		// Run the analysis queue that the loader just scheduled, so the
		// saved project reflects what an end-user would see after the
		// patch has been imported AND analyzed.
		int analyzeTx = program.startTransaction("run-analysis");
		try {
			AutoAnalysisManager.getAnalysisManager(program)
					.startAnalysis(TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(analyzeTx, true);
		}
		int postPatchFunctionCount =
			program.getFunctionManager().getFunctionCount();
		assertTrue(
			"Patch analysis should add functions (pre=" +
				preLoadFunctionCount + " post=" + postPatchFunctionCount +
				")",
			postPatchFunctionCount > preLoadFunctionCount);

		// The firmware patch carries its own mtusr,itb writer at a higher
		// address than the ROM's writer, so the ITB analyzer should
		// re-elect the firmware value and override the ROM-resident one.
		// (Before the analyzer was taught to discover writers on incremental
		// runs, the patch's writer went unseen and the ROM ITB stuck.)
		BigInteger fwItb = readItb();
		assertNotNull("Patch analysis should leave an ITB elected", fwItb);
		assertNotEquals(
			"Firmware patch must override the ROM ITB " +
				"(rom=0x" + romItb.toString(16) +
				", post-patch=0x" + fwItb.toString(16) + ")",
			romItb, fwItb);

		// Save the resulting program to a stable on-disk Ghidra project so
		// it can be opened in the GUI for inspection.  Path is printed to
		// stdout so the test runner reports it.
		saveOutputProject();
	}

	private void saveOutputProject() throws Exception {
		// Saving as a packed .gzf file -- portable, single-file, openable
		// in any Ghidra GUI via "File > Restore Project" or by drag-drop
		// onto the project tree.  Avoids the consumer/ownership mismatch
		// that GhidraProject.saveAs hits when the program was created
		// outside the project (via ProgramBuilder here).
		File outDir = new File("build/test-output").getAbsoluteFile();
		outDir.mkdirs();
		File out = new File(outDir, "mt7663_load_flow.gzf");
		if (out.exists() && !out.delete()) {
			throw new java.io.IOException(
				"Failed to delete previous output: " + out);
		}
		program.saveToPackedFile(out, TaskMonitor.DUMMY);
		System.out.println("MT7663 LOAD FLOW PROJECT SAVED TO: " +
			out.getAbsolutePath());
	}

	/**
	 * Stage 1: import the ROM via the production {@link BinaryLoader}.
	 * Going through the real loader pipeline (rather than fabricating a
	 * {@code ProgramBuilder} program) is what makes the pspec's
	 * {@code default_memory_blocks} ({@code ILM_ROM}, {@code ILM_RAM},
	 * {@code DLM}, {@code csr}) materialize with the right permissions,
	 * and what makes {@code AbstractProgramLoader.applyProcessorLabels}
	 * fire -- which is where the CSR alias symbols ({@code psw},
	 * {@code ipsw}, {@code ivb}, ...) and every memory-mapped register
	 * get their labels.
	 */
	private void loadRom() throws Exception {
		BinaryLoader loader = new BinaryLoader();
		try (ByteProvider provider =
			new ByteArrayProvider("mt7663_00000000.bin", romBytes)) {

			LoadSpec spec = findLoadSpec(loader, provider, LANGUAGE);
			List<Option> options =
				new ArrayList<>(loader.getDefaultOptions(provider, spec,
					/*domainObject=*/ null, /*loadIntoProgram=*/ false,
					/*mirrorFsLayout=*/ false));
			// Name the loaded block "ILM_ROM" so the byte payload IS the
			// pspec's ILM_ROM region; createDefaultMemoryBlocks will then
			// see ILM_ROM already exists and skip it, leaving us with one
			// initialized ILM_ROM (with ROM bytes) plus the uninitialized
			// ILM_RAM / DLM / csr blocks the pspec also declares.
			setOptionString(options, BinaryLoader.OPTION_NAME_BLOCK_NAME,
				"ILM_ROM");

			Loader.ImporterSettings settings = new Loader.ImporterSettings(
				provider, "mt7663_00000000.bin", /*project=*/ null,
				/*projectRootPath=*/ "/", /*mirrorFsLayout=*/ false, spec,
				options, /*consumer=*/ this, new MessageLog(),
				TaskMonitor.DUMMY);

			LoadResults<? extends DomainObject> results = loader.load(settings);
			Loaded<? extends DomainObject> loaded = results.iterator().next();
			DomainObject obj = loaded.getDomainObject(this);
			assertTrue("BinaryLoader must produce a Program",
				obj instanceof Program);
			program = (Program) obj;
		}
	}

	private static LoadSpec findLoadSpec(BinaryLoader loader,
			ByteProvider provider, String languageId) throws Exception {
		for (LoadSpec ls : loader.findSupportedLoadSpecs(provider)) {
			if (languageId.equals(ls.getLanguageCompilerSpec()
					.getLanguageID().getIdAsString())) {
				return ls;
			}
		}
		throw new AssertionError("no BinaryLoader LoadSpec for " + languageId);
	}

	private static void setOptionString(List<Option> options, String name,
			String value) {
		for (int i = 0; i < options.size(); i++) {
			if (name.equals(options.get(i).getName())) {
				options.set(i, Option.newString(name).value(value).build());
				return;
			}
		}
		options.add(Option.newString(name).value(value).build());
	}

	/**
	 * Stage 3: drop the firmware patch into the existing program
	 * using the production loader.  This is the same code path used
	 * by Ghidra's "Add to Program" import flow.
	 */
	private void loadPatch() throws Exception {
		try (ByteProvider provider =
			new ByteArrayProvider("mt7663_patch_e2_hdr.bin", patchBytes)) {

			Mt76ConnacPatchLoader loader = new Mt76ConnacPatchLoader();

			var specs = loader.findSupportedLoadSpecs(provider);
			assertFalse("Mt76ConnacPatchLoader must recognize the patch file",
				specs.isEmpty());
			LoadSpec spec = specs.iterator().next();

			List<Option> options =
				new ArrayList<>(loader.getDefaultOptions(provider, spec,
					program, /*loadIntoProgram=*/ true,
					/*mirrorFsLayout=*/ false));

			Loader.ImporterSettings settings = new Loader.ImporterSettings(
				provider, "mt7663_patch_e2_hdr.bin", /*project=*/ null,
				/*projectRootPath=*/ "/", /*mirrorFsLayout=*/ false, spec,
				options, /*consumer=*/ this, new MessageLog(),
				TaskMonitor.DUMMY);

			int tx = program.startTransaction("load-patch");
			try {
				loader.loadInto(program, settings);
			}
			finally {
				program.endTransaction(tx, true);
			}
		}
	}

	private byte[] readResource(String classpathPath) throws Exception {
		try (InputStream in = getClass().getResourceAsStream(classpathPath)) {
			assertNotNull("test resource not on classpath: " + classpathPath,
				in);
			return in.readAllBytes();
		}
	}

	private int countInitializedBlocks(Memory mem) {
		int n = 0;
		for (MemoryBlock b : mem.getBlocks()) {
			if (b.isInitialized()) {
				n++;
			}
		}
		return n;
	}

	private Address addr(long off) {
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		return space.getAddress(off);
	}

	/** Read the ITB register's currently-tracked value from program context. */
	private BigInteger readItb() {
		Register itb = program.getLanguage().getRegister("itb");
		assertNotNull("itb register must exist in language", itb);
		ProgramContext pc = program.getProgramContext();
		// Sample at a couple of points: the active ITB is propagated as a
		// program-wide context value, so anywhere in defined code works.
		BigInteger v = pc.getValue(itb, addr(0x100), /*signed=*/ false);
		if (v == null) {
			v = pc.getValue(itb, addr(PATCH_LOAD_ADDR), false);
		}
		return v;
	}
}
