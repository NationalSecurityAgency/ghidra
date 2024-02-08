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
/*
 * ProgramDiffTest.java
 *
 * Created on January 3, 2002, 9:55 AM
 */

package ghidra.program.util;

import static org.junit.Assert.*;

import java.util.Set;

import org.junit.*;

import ghidra.program.database.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;

/**
 * <CODE>ProgramDiffTest</CODE> tests the <CODE>ProgramDiff</CODE> class
 * to verify it correctly determines various types of program differences.
 * The setup for this test class loads two programs that were saved to the
 * testdata directory as XML. The tests will determine the differences between
 * these two programs.
 */
public class ProgramDiffMergeOverlayTest extends AbstractProgramDiffTest {

	protected MergeTestFacilitator mtf;
	protected Program originalProgram;
	protected Program latestProgram;
	protected Program myProgram;
	protected Program resultProgram;

	public ProgramDiffMergeOverlayTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		fixupGUI();
		mtf = new MergeTestFacilitator();
		TestEnv testEnv = mtf.getTestEnvironment();
		testEnv.getTool().setToolName("TestTool");
	}

	@After
	public void tearDown() throws Exception {
		try {
			if (resultProgram != null) {
				resultProgram.flushEvents();
			}
			waitForSwing();

		}
		catch (Exception e) {
			e.printStackTrace();
		}
		mtf.dispose();// Get rid of the merge environment.

	}

	@Test
	public void testDiffMergeOverlayFunctionTags() throws Exception {
		mtf.initialize("overlayCalc", new MultiOverlayProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				super.modifyLatest(program);
				try {
					Listing listing = program.getListing();

					Function f = listing.getFunctionAt(addr(program, "OtherOverlay:0x01001680"));
					f.addTag("Tag1");
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// P2 program
				super.modifyPrivate(program);
				try {
					Listing listing = program.getListing();
					Function f = listing.getFunctionAt(addr(program, "SomeOverlay:0x01001780"));
					f.addTag("Tag2");
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		p1 = mtf.getResultProgram();
		p2 = mtf.getPrivateProgram();

		AddressSet as = new AddressSet();
		as.addRange(addr(p1, "SomeOverlay::01001780"), addr(p1, "SomeOverlay::01001780"));
		as.addRange(addr(p1, "OtherOverlay::01001680"), addr(p1, "OtherOverlay::01001680"));

		ProgramMergeManager programMerge = new ProgramMergeManager(p1, p2, TaskMonitor.DUMMY);
		programMerge.setDiffFilter(new ProgramDiffFilter(
			ProgramDiffFilter.FUNCTION_DIFFS | ProgramDiffFilter.FUNCTION_TAG_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS | ProgramMergeFilter.FUNCTION_TAGS,
				ProgramMergeFilter.REPLACE));
		assertEquals(as, programMerge.getFilteredDifferences());

		p1.withTransaction("merge", () -> programMerge.merge(as, TaskMonitor.DUMMY));
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());

		Listing listing1 = p1.getListing();
		Function f = listing1.getFunctionAt(addr(p1, "SomeOverlay:0x01001780"));
		assertNotNull(f);
		Set<FunctionTag> tags = f.getTags();
		assertEquals(1, tags.size());
		FunctionTag tag = tags.iterator().next();
		assertEquals("Tag2", tag.getName());
	}

	@Test
	public void testDiffMergeOverlayFunctions() throws Exception {
		mtf.initialize("overlayCalc", new MultiOverlayProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				super.modifyLatest(program);
				try {
					Listing listing = program.getListing();
					Function f = listing.getFunctionAt(addr(program, "OtherOverlay:0x01001680"));
					f.setCallingConvention(CompilerSpec.CALLING_CONVENTION_thiscall);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// P2 program
				super.modifyPrivate(program);
				try {
					Listing listing = program.getListing();
					Function f = listing.getFunctionAt(addr(program, "SomeOverlay:0x01001780"));
					f.setCallingConvention(CompilerSpec.CALLING_CONVENTION_thiscall);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		p1 = mtf.getResultProgram();
		p2 = mtf.getPrivateProgram();

		programDiff = new ProgramDiff(p1, p2);
		AddressSet as = new AddressSet();
		as.addRange(addr(p1, "SomeOverlay::01001780"), addr(p1, "SomeOverlay::01001780"));
		as.addRange(addr(p1, "OtherOverlay::01001680"), addr(p1, "OtherOverlay::01001680"));
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));

		ProgramMergeManager programMerge = new ProgramMergeManager(p1, p2, TaskMonitor.DUMMY);
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
		assertEquals(as, programMerge.getFilteredDifferences());

		p1.withTransaction("merge", () -> programMerge.merge(as, TaskMonitor.DUMMY));
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());

		Listing listing1 = p1.getListing();
		assertNotNull(listing1.getFunctionAt(addr(p1, "OtherOverlay:0x01001680")));
		assertNotNull(listing1.getFunctionAt(addr(p1, "SomeOverlay:0x01001780")));
	}

	@Test
	public void testDiffMergeOverlayLabels() throws Exception {
		mtf.initialize("overlayCalc", new MultiOverlayProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				super.modifyLatest(program);
				try {
					SymbolTable st = program.getSymbolTable();
					st.createLabel(addr(program, "SomeOverlay::01001630"), "OVL1630",
						SourceType.USER_DEFINED);
					st.createLabel(addr(program, "OtherOverlay::01001866"), "OVL1866",
						SourceType.USER_DEFINED);

				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// P2 program
				super.modifyPrivate(program);
				try {
					SymbolTable st = program.getSymbolTable();
					st.createLabel(addr(program, "SomeOverlay::01001889"), "OVL1889",
						SourceType.USER_DEFINED);
					st.createLabel(addr(program, "OtherOverlay::01001646"), "OVL1646",
						SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		p1 = mtf.getResultProgram();
		p2 = mtf.getPrivateProgram();

		programDiff = new ProgramDiff(p1, p2);
		final AddressSet as = new AddressSet();
		as.addRange(addr(p1, "SomeOverlay::01001630"), addr(p1, "SomeOverlay::01001630"));
		as.addRange(addr(p1, "SomeOverlay::01001889"), addr(p1, "SomeOverlay::01001889"));
		as.addRange(addr(p1, "OtherOverlay::01001646"), addr(p1, "OtherOverlay::01001646"));
		as.addRange(addr(p1, "OtherOverlay::01001866"), addr(p1, "OtherOverlay::01001866"));
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));

		ProgramMergeManager programMerge = new ProgramMergeManager(p1, p2, TaskMonitor.DUMMY);
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.SYMBOLS | ProgramMergeFilter.PRIMARY_SYMBOL,
				ProgramMergeFilter.REPLACE));
		assertEquals(as, programMerge.getFilteredDifferences());

		p1.withTransaction("merge", () -> programMerge.merge(as, TaskMonitor.DUMMY));
		AddressSet as2 = new AddressSet();
		// Symbol removal not handled - only replace or add
		as2.addRange(addr(p1, "OtherOverlay::01001866"), addr(p1, "OtherOverlay::01001866"));
		assertEquals(as2, programMerge.getFilteredDifferences());

		SymbolTable st1 = p1.getSymbolTable();
		assertNotNull(st1.getSymbol("OVL1889", addr(p1, "SomeOverlay::01001889"), null));
		assertNotNull(st1.getSymbol("OVL1646", addr(p1, "OtherOverlay::01001646"), null));
	}

//	private void printAddressSet(AddressSetView as) {
//		System.out.println("=====");
//		for (AddressRange r : as) {
//			System.out.println("[" + r.getMinAddress() + "," + r.getMaxAddress() + "]");
//		}
//		System.out.println("-----");
//	}

	private class MultiOverlayProgramModifierListener implements ProgramModifierListener {

		@Override
		public void modifyLatest(ProgramDB program) {
			// P1 program
			try {
				program.getMemory()
						.createInitializedBlock("SomeOverlay", addr(program, "0x01001630"), 0x200,
							(byte) 0, TaskMonitor.DUMMY, true);
				program.getMemory()
						.createInitializedBlock("OtherOverlay", addr(program, "0x01001630"), 0x300,
							(byte) 0, TaskMonitor.DUMMY, true);

				initProgramCommon(program);
			}
			catch (Exception e) {
				Assert.fail(e.getMessage());
			}
		}

		@Override
		public void modifyPrivate(ProgramDB program) {
			// P2 program
			try {
				program.getMemory()
						.createInitializedBlock("OtherOverlay", addr(program, "0x01001630"), 0x200,
							(byte) 0, TaskMonitor.DUMMY, true);
				program.getMemory()
						.createInitializedBlock("SomeOverlay", addr(program, "0x01001630"), 0x300,
							(byte) 0, TaskMonitor.DUMMY, true);

				initProgramCommon(program);
			}
			catch (Exception e) {
				Assert.fail(e.getMessage());
			}
		}
	}

	private static void initProgramCommon(Program program) throws Exception {
		Listing listing = program.getListing();

		Address a = addr(program, "OtherOverlay:0x01001680");
		listing.createFunction("oFunc", a, new AddressSet(a, a), SourceType.USER_DEFINED);

		a = addr(program, "SomeOverlay:0x01001780");
		listing.createFunction("sFunc", a, new AddressSet(a, a), SourceType.USER_DEFINED);

	}

}
