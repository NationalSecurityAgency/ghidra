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
package ghidra.app.util.pdb.pdbapplicator;

import static org.junit.Assert.*;

import java.util.*;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.Compile3MsSymbol;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.PeCoffSectionMsSymbol;
import ghidra.app.util.pdb.pdbapplicator.PdbAddressCalculator.*;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Tests for PDB {@link PdbAddressCalculator}s.
 */
public class PdbAddressCalculatorTest extends AbstractGenericTest {

	private Program program;
	private AddressSpace addressSpace = null;

	private AbstractPdb pdb;
	private static Processor processor;

	private Address imageBase = null;
	private long originalImageBase = 0L;
	private List<ImageSectionHeader> imageSectionHeaders = null;
	private List<ImageSectionHeader> imageSectionHeadersOrig = null;
	private SortedMap<Long, Long> omapFromSource = null;
	private List<SegmentMapDescription> segmentMapDescriptions = null;
	private List<SegmentMapDescription> segmentMapDescriptionsZeroOffsets = null;
	private List<PeCoffSectionMsSymbol> peCoffSectionSymbols = null;
	private MemoryBlock[] memoryBlocks = null;

	// Modeled from MemoryMapProvider1Test
	private Program buildProgram(String programName, long imageBaseOffset) throws Exception {
		ProgramBuilder builder = new ProgramBuilder(programName, ProgramBuilder._TOY);
		MemoryBlock[] blocks = new MemoryBlock[3];
		blocks[0] = builder.createMemory(".sect1", Long.toHexString(0x1000), 0x1000);
		blocks[1] = builder.createMemory(".sect2", Long.toHexString(0x2000), 0x1000);
		blocks[2] = builder.createMemory(".sect3", Long.toHexString(0x3000), 0x1000);
		Program newProgram = builder.getProgram();

		int transactionID = newProgram.startTransaction("Test Transaction");
		newProgram.setImageBase(
			newProgram.getAddressFactory().getDefaultAddressSpace().getAddress(imageBaseOffset),
			true);
		newProgram.endTransaction(transactionID, true);

		return newProgram;
	}

	private Address addr(long offset) {
		return addressSpace.getAddress(offset);
	}

	// Modeled from SymbolsTest
	private AbstractPdb buildPdb() {
		try (DummyPdb700 dummyPdb700 = new DummyPdb700(4096, 4096, 4096, 4096)) {
			// Important: Must also use this processor value in any tests below that need it to
			// ensure consistency across the tests.  We are setting it in the pdb here (in the
			// static assignment block), but we do not know the order that any tests are run,
			// so having the same value  will ensure consistent results.
			processor = Processor.I8080;
			dummyPdb700.setTargetProcessor(processor);
			return dummyPdb700;
		}
		catch (Exception e) {
			fail("Error in static initialization of test: " + e);
			return null; // to satisfy compile warning
		}
	}

	private List<ImageSectionHeader> setupImageSectionHeaders(AbstractPdb myPdb) {
		List<ImageSectionHeader> headers = new ArrayList<>();
		headers.add(PdbTestUtils.createImageSectionHeader(myPdb, ".sect1", 0x1000L, 0x1000L));
		headers.add(PdbTestUtils.createImageSectionHeader(myPdb, ".sect2", 0x2000L, 0x1000L));
		headers.add(PdbTestUtils.createImageSectionHeader(myPdb, ".sect3", 0x3000L, 0x1000L));
		return headers;
	}

	private List<ImageSectionHeader> setupImageSectionHeadersOrig(AbstractPdb myPdb) {
		List<ImageSectionHeader> headers = new ArrayList<>();
		headers.add(PdbTestUtils.createImageSectionHeader(myPdb, ".sect1", 0x1000L, 0x3000L));
		headers.add(PdbTestUtils.createImageSectionHeader(myPdb, ".sect2", 0x4000L, 0x3000L));
		headers.add(PdbTestUtils.createImageSectionHeader(myPdb, ".sect3", 0x7000L, 0x3000L));
		return headers;
	}

	private SortedMap<Long, Long> setupOmapFromSource() {
		SortedMap<Long, Long> omap = new TreeMap<>();
		omap.put(0x1000L, 0x19000L);
		omap.put(0x4000L, 0x28000L);
		omap.put(0x7000L, 0x37000L);
		return omap;
	}

	private List<SegmentMapDescription> setupSegmentMapDescriptions(AbstractPdb myPdb) {
		List<SegmentMapDescription> segments = new ArrayList<>();
		segments.add(PdbTestUtils.createSegmentMapDescription(myPdb, 0x1000L, 0x1000));
		segments.add(PdbTestUtils.createSegmentMapDescription(myPdb, 0x2000L, 0x1000));
		segments.add(PdbTestUtils.createSegmentMapDescription(myPdb, 0x3000L, 0x1000));
		return segments;
	}

	private List<SegmentMapDescription> setupSegmentMapDescriptionsZeroOffsets(AbstractPdb myPdb) {
		List<SegmentMapDescription> segments = new ArrayList<>();
		segments.add(PdbTestUtils.createSegmentMapDescription(myPdb, 0x0L, 0x1000));
		segments.add(PdbTestUtils.createSegmentMapDescription(myPdb, 0x0L, 0x1000));
		segments.add(PdbTestUtils.createSegmentMapDescription(myPdb, 0x0L, 0x1000));
		return segments;
	}

	private List<PeCoffSectionMsSymbol> setupPeCoffSectionSymbols(AbstractPdb myPdb) {
		List<PeCoffSectionMsSymbol> symbols = new ArrayList<>();
		symbols.add(PdbTestUtils.createPeCoffSectionMsSymbol(myPdb, 1, 0x1000, 0x1000, ".sect1"));
		symbols.add(PdbTestUtils.createPeCoffSectionMsSymbol(myPdb, 2, 0x2000, 0x1000, ".sect2"));
		symbols.add(PdbTestUtils.createPeCoffSectionMsSymbol(myPdb, 3, 0x3000, 0x1000, ".sect3"));
		return symbols;
	}

	//----------------------------------------------------------------------------------------------
	@Before
	public void setUp() throws Exception {
		program = buildProgram("testProgram", 0x400000L);
		pdb = buildPdb();
		addressSpace = program.getAddressFactory().getDefaultAddressSpace();

		imageBase = program.getImageBase();

		memoryBlocks = program.getMemory().getBlocks();
		originalImageBase = 0L;

		imageSectionHeaders = setupImageSectionHeaders(pdb);
		imageSectionHeadersOrig = setupImageSectionHeadersOrig(pdb);
		omapFromSource = setupOmapFromSource();

		segmentMapDescriptions = setupSegmentMapDescriptions(pdb);
		segmentMapDescriptionsZeroOffsets = setupSegmentMapDescriptionsZeroOffsets(pdb);

		peCoffSectionSymbols = setupPeCoffSectionSymbols(pdb);
	}

	//----------------------------------------------------------------------------------------------
	@Test
	public void testImageHeaderAddressCalculator() throws Exception {
		PdbAddressCalculator calculator =
			new PdbAddressCalculator.ImageHeaderAddressCalculator(imageBase, imageSectionHeaders);

		Address expectedAddress = addr(0x401000L);
		Address calculatedAddress = calculator.getAddress(1, 0x0L);
		assertEquals(expectedAddress, calculatedAddress);

		expectedAddress = addr(0x401100L);
		calculatedAddress = calculator.getAddress(1, 0x100L);
		assertEquals(expectedAddress, calculatedAddress);

		expectedAddress = addr(0x402200L);
		calculatedAddress = calculator.getAddress(2, 0x200L);
		assertEquals(expectedAddress, calculatedAddress);
	}

	@Test
	public void testImageHeaderWithOmapAddressCalculator() throws Exception {
		PdbAddressCalculator calculator =
			new PdbAddressCalculator.ImageHeaderWithOmapAddressCalculator(imageBase,
				imageSectionHeadersOrig, omapFromSource);

		Address expectedAddress = addr(0x419000L);
		Address calculatedAddress = calculator.getAddress(1, 0x0L);
		assertEquals(expectedAddress, calculatedAddress);

		expectedAddress = addr(0x419100L);
		calculatedAddress = calculator.getAddress(1, 0x100L);
		assertEquals(expectedAddress, calculatedAddress);

		expectedAddress = addr(0x428200L);
		calculatedAddress = calculator.getAddress(2, 0x200L);
		assertEquals(expectedAddress, calculatedAddress);
	}

	@Test
	public void testSegmentMapAddressCalculator() throws Exception {
		PdbAddressCalculator calculator =
			new PdbAddressCalculator.SegmentMapAddressCalculator(imageBase, segmentMapDescriptions);

		Address expectedAddress = addr(0x401000L);
		Address calculatedAddress = calculator.getAddress(1, 0x0L);
		assertEquals(expectedAddress, calculatedAddress);

		expectedAddress = addr(0x401100L);
		calculatedAddress = calculator.getAddress(1, 0x100L);
		assertEquals(expectedAddress, calculatedAddress);

		expectedAddress = addr(0x402200L);
		calculatedAddress = calculator.getAddress(2, 0x200L);
		assertEquals(expectedAddress, calculatedAddress);
	}

	@Test
	public void testSegmentMapAddressCalculatorWithSynthesis() throws Exception {
		PdbAddressCalculator calculator = new PdbAddressCalculator.SegmentMapAddressCalculator(
			imageBase, segmentMapDescriptionsZeroOffsets);

		Address expectedAddress = addr(0x401000L);
		Address calculatedAddress = calculator.getAddress(1, 0x0L);
		assertEquals(expectedAddress, calculatedAddress);

		expectedAddress = addr(0x401100L);
		calculatedAddress = calculator.getAddress(1, 0x100L);
		assertEquals(expectedAddress, calculatedAddress);

		expectedAddress = addr(0x402200L);
		calculatedAddress = calculator.getAddress(2, 0x200L);
		assertEquals(expectedAddress, calculatedAddress);
	}

	@Test
	public void testPeCoffSectionAddressCalculator() throws Exception {
		PdbAddressCalculator calculator = new PdbAddressCalculator.PeCoffSectionAddressCalculator(
			imageBase, originalImageBase, peCoffSectionSymbols);

		Address expectedAddress = addr(0x401000L);
		Address calculatedAddress = calculator.getAddress(1, 0x0L);
		assertEquals(expectedAddress, calculatedAddress);

		expectedAddress = addr(0x401100L);
		calculatedAddress = calculator.getAddress(1, 0x100L);
		assertEquals(expectedAddress, calculatedAddress);

		expectedAddress = addr(0x402200L);
		calculatedAddress = calculator.getAddress(2, 0x200L);
		assertEquals(expectedAddress, calculatedAddress);
	}

	@Test
	public void testMemoryMapAddressCalculator() throws Exception {
		PdbAddressCalculator calculator =
			new PdbAddressCalculator.MemoryMapAddressCalculator(imageBase, memoryBlocks);

		Address expectedAddress = addr(0x401000L);
		Address calculatedAddress = calculator.getAddress(1, 0x0L);
		assertEquals(expectedAddress, calculatedAddress);

		expectedAddress = addr(0x401100L);
		calculatedAddress = calculator.getAddress(1, 0x100L);
		assertEquals(expectedAddress, calculatedAddress);

		expectedAddress = addr(0x402200L);
		calculatedAddress = calculator.getAddress(2, 0x200L);
		assertEquals(expectedAddress, calculatedAddress);
	}

	//----------------------------------------------------------------------------------------------
	@Test
	public void testAddressCorrectionValue() throws Exception {
		Compile3MsSymbol compileSymbol;
		long correction;

		StubPdbApplicator applicator = new StubPdbApplicator();
		applicator.setProgram(program).setPdb(pdb).setOriginalImageBase(originalImageBase);

		compileSymbol = PdbTestUtils.createCompile3MsSymbol(pdb, "anythingbutmap2pdb");
		applicator.setLinkerModuleCompileSymbol(compileSymbol);
		correction = PdbAddressCalculator.getCorrection(applicator);
		assertEquals(0x0L, correction);

		compileSymbol = PdbTestUtils.createCompile3MsSymbol(pdb, "map2pdb");
		applicator.setLinkerModuleCompileSymbol(compileSymbol);
		correction = PdbAddressCalculator.getCorrection(applicator);
		assertEquals(originalImageBase, correction);
	}

	@Test
	public void testAddressCalculatorFactory() throws Exception {
		PdbAddressCalculator calculator;
		Compile3MsSymbol compileSymbol;
		Address expectedAddress;
		Address calculatedAddress;
		StubPdbApplicator applicator = new StubPdbApplicator();

		// These applicator modifications and tests are done in an order based upon the known
		// order of exclusion of PdbAddressCalculators, but in the reverse order to ensure the
		// exclusions.

		// Make it seem as though PDB does not have debug info
		((DummyPdb700) pdb).setDebugInfoAvailable(false);

		applicator.setProgram(program).setPdb(pdb);
		calculator = PdbAddressCalculator.chooseAddressCalculator(applicator, imageBase);
		assertTrue(calculator instanceof MemoryMapAddressCalculator);

		applicator.setLinkerPeCoffSectionSymbols(peCoffSectionSymbols);
		compileSymbol = PdbTestUtils.createCompile3MsSymbol(pdb, "anythingbutmap2pdb");
		applicator.setLinkerModuleCompileSymbol(compileSymbol);
		calculator = PdbAddressCalculator.chooseAddressCalculator(applicator, imageBase);
		assertTrue(calculator instanceof PeCoffSectionAddressCalculator);
		// test address value.  maybe??
		expectedAddress = addr(0x402200L);
		calculatedAddress = calculator.getAddress(2, 0x200L);
		assertEquals(expectedAddress, calculatedAddress);

		compileSymbol = PdbTestUtils.createCompile3MsSymbol(pdb, "map2pdb");
		applicator.setLinkerModuleCompileSymbol(compileSymbol);
		calculator = PdbAddressCalculator.chooseAddressCalculator(applicator, imageBase);
		assertTrue(calculator instanceof PeCoffSectionAddressCalculator);
		// test address value.  maybe??
		expectedAddress = addr(0x402200L);
		calculatedAddress = calculator.getAddress(2, 0x200L);
		assertEquals(expectedAddress, calculatedAddress);

		// Make debug info available again and get nested resources
		((DummyPdb700) pdb).setDebugInfoAvailable(true);
		PdbDebugInfo dbi = pdb.getDebugInfo();
		assertTrue(dbi instanceof DummyDebugInfoNew);
		DummyDebugInfoNew dummyDebugInfoNew = (DummyDebugInfoNew) dbi;
		DebugData debugData = dummyDebugInfoNew.getDebugData();
		assertTrue(debugData instanceof DummyDebugData);
		DummyDebugData dummyDebugData = (DummyDebugData) debugData;

		dummyDebugData.setImageSectionHeaders(null);
		dummyDebugData.setImageSectionHeadersOrig(null);
		dummyDebugData.setOmapFromSource(null);
		dummyDebugInfoNew.setSegmentMapList(segmentMapDescriptions);
		calculator = PdbAddressCalculator.chooseAddressCalculator(applicator, imageBase);
		assertTrue(calculator instanceof SegmentMapAddressCalculator);
		expectedAddress = addr(0x402200L);
		calculatedAddress = calculator.getAddress(2, 0x200L);
		assertEquals(expectedAddress, calculatedAddress);

		dummyDebugData.setImageSectionHeaders(imageSectionHeaders);
		calculator = PdbAddressCalculator.chooseAddressCalculator(applicator, imageBase);
		assertTrue(calculator instanceof ImageHeaderAddressCalculator);
		expectedAddress = addr(0x402200L);
		calculatedAddress = calculator.getAddress(2, 0x200L);
		assertEquals(expectedAddress, calculatedAddress);

		dummyDebugData.setImageSectionHeadersOrig(imageSectionHeadersOrig);
		calculator = PdbAddressCalculator.chooseAddressCalculator(applicator, imageBase);
		assertTrue(calculator instanceof ImageHeaderAddressCalculator);
		expectedAddress = addr(0x404200L);
		calculatedAddress = calculator.getAddress(2, 0x200L);
		assertEquals(expectedAddress, calculatedAddress);

		dummyDebugData.setOmapFromSource(omapFromSource);
		calculator = PdbAddressCalculator.chooseAddressCalculator(applicator, imageBase);
		assertTrue(calculator instanceof ImageHeaderWithOmapAddressCalculator);
		expectedAddress = addr(0x428200L);
		calculatedAddress = calculator.getAddress(2, 0x200L);
		assertEquals(expectedAddress, calculatedAddress);

	}

}
