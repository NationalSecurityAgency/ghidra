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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.*;

import ghidra.program.database.*;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;

/**
 * <CODE>ProgramDiffTest</CODE> tests the <CODE>ProgramDiff</CODE> class
 * to verify it correctly determines various types of program differences.
 * The setup for this test class loads two programs that were saved to the
 * testdata directory as XML. The tests will determine the differences between
 * these two programs.
 */
public class ProgramDiff2Test extends AbstractProgramDiffTest {

	protected MergeTestFacilitator mtf;
	protected Program originalProgram;
	protected Program latestProgram;
	protected Program myProgram;
	protected Program resultProgram;

	public ProgramDiff2Test() {
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
			waitForPostedSwingRunnables();

		}
		catch (Exception e) {
			e.printStackTrace();
		}
		mtf.dispose();// Get rid of the merge environment.

	}

	/**
	 * Test that ProgramDiff recognizes that the 2 programs have the same
	 * address spaces.
	 */
	@Test
	public void testDiffNamespaceLabels() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					SymbolTable st = program.getSymbolTable();
					Namespace namespace = program.getGlobalNamespace();
					try {
						st.createLabel(addr(program, "0x010058f7"), "MY.DLL_SampleLabel", namespace,
							SourceType.USER_DEFINED);
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// P2 program
				int txId = program.startTransaction("Modify Program 2");
				boolean commit = false;
				try {
					SymbolTable st = program.getSymbolTable();
					Namespace namespace;
					try {
						namespace = st.createNameSpace(program.getGlobalNamespace(), "MY.DLL",
							SourceType.USER_DEFINED);
						st.createLabel(addr(program, "0x010058f7"), "SampleLabel", namespace,
							SourceType.USER_DEFINED);
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		p1 = mtf.getResultProgram();
		p2 = mtf.getPrivateProgram();

		AddressSet setToDiff = new AddressSet(addr(p1, "0x10058f6"), addr(p1, "0x10058fa"));
		programDiff = new ProgramDiff(p1, p2, setToDiff);
		AddressSet as = new AddressSet();
		as.addRange(addr(p1, "0x10058f7"), addr(p1, "0x10058f7"));
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	@Test
	public void testSameSymbolSource() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					SymbolTable st = program.getSymbolTable();
					Namespace namespace = program.getGlobalNamespace();
					try {
						createDataReference(program, addr(program, "0x01001e81"),
							addr(program, "0x01001ea0"));
						st.createLabel(addr(program, "0x01001ea9"), "One", namespace,
							SourceType.USER_DEFINED);
						st.createLabel(addr(program, "0x01001eb5"), "Two", namespace,
							SourceType.IMPORTED);
						st.createLabel(addr(program, "0x01001ebc"), "Three", namespace,
							SourceType.ANALYSIS);
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					try {
						st.createLabel(addr(program, "0x01001ec6"), "LAB_01001ec6", namespace,
							SourceType.DEFAULT);
						Assert.fail("Shouldn't be able to create symbol for a default label.");
					}
					catch (Exception e) {
						// good; expected
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// P2 program
				int txId = program.startTransaction("Modify Program 2");
				boolean commit = false;
				try {
					SymbolTable st = program.getSymbolTable();
					Namespace namespace = program.getGlobalNamespace();
					try {
						createDataReference(program, addr(program, "0x01001e81"),
							addr(program, "0x01001ea0"));
						st.createLabel(addr(program, "0x01001ea9"), "One", namespace,
							SourceType.USER_DEFINED);
						st.createLabel(addr(program, "0x01001eb5"), "Two", namespace,
							SourceType.IMPORTED);
						st.createLabel(addr(program, "0x01001ebc"), "Three", namespace,
							SourceType.ANALYSIS);
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					try {
						st.createLabel(addr(program, "0x01001ec6"), "LAB_01001ec6", namespace,
							SourceType.DEFAULT);
						Assert.fail("Shouldn't be able to create symbol for a default label.");
					}
					catch (Exception e) {
						// good; expected
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		p1 = mtf.getResultProgram();
		p2 = mtf.getPrivateProgram();

		programDiff = new ProgramDiff(p1, p2);
		AddressSet as = new AddressSet();
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	@Test
	public void testDiffSymbolSource() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					SymbolTable st = program.getSymbolTable();
					Namespace namespace = program.getGlobalNamespace();
					try {
						program.getFunctionManager()
							.getFunctionAt(addr(program, "0x100248f"))
							.getSymbol()
							.setName("Bud", SourceType.IMPORTED);
						createDataReference(program, addr(program, "0x01001e81"),
							addr(program, "0x01001ea0"));
						Symbol[] symbols = st.getSymbols(addr(program, "0x01001ea0"));
						symbols[0].setName("Zero", SourceType.IMPORTED);
						st.createLabel(addr(program, "0x01001ea9"), "One", namespace,
							SourceType.USER_DEFINED);
						st.createLabel(addr(program, "0x01001eb5"), "Two", namespace,
							SourceType.IMPORTED);
						st.createLabel(addr(program, "0x01001ebc"), "Three", namespace,
							SourceType.ANALYSIS);
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// P2 program
				int txId = program.startTransaction("Modify Program 2");
				boolean commit = false;
				try {
					SymbolTable st = program.getSymbolTable();
					Namespace namespace = program.getGlobalNamespace();
					try {
						program.getFunctionManager()
							.getFunctionAt(addr(program, "0x100248f"))
							.getSymbol()
							.setName("Bud", SourceType.ANALYSIS);
						createDataReference(program, addr(program, "0x01001e81"),
							addr(program, "0x01001ea0"));// Leave this as default.
						Symbol[] symbols = st.getSymbols(addr(program, "0x01001ea0"));
						symbols[0].setName("Zero", SourceType.ANALYSIS);
						st.createLabel(addr(program, "0x01001ea9"), "One", namespace,
							SourceType.IMPORTED);
						st.createLabel(addr(program, "0x01001eb5"), "Two", namespace,
							SourceType.ANALYSIS);
						st.createLabel(addr(program, "0x01001ebc"), "Three", namespace,
							SourceType.USER_DEFINED);
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		p1 = mtf.getResultProgram();
		p2 = mtf.getPrivateProgram();

		programDiff = new ProgramDiff(p1, p2);
		AddressSet as = new AddressSet();
		as.addRange(addr(p1, "0x01001ea0"), addr(p1, "0x01001ea0"));
		as.addRange(addr(p1, "0x01001ea9"), addr(p1, "0x01001ea9"));
		as.addRange(addr(p1, "0x01001eb5"), addr(p1, "0x01001eb5"));
		as.addRange(addr(p1, "0x01001ebc"), addr(p1, "0x01001ebc"));
		as.addRange(addr(p1, "0x100248f"), addr(p1, "0x100248f"));
		as.addRange(addr(p1, "0x1002691"), addr(p1, "0x1002691"));// Label in the 100248f namespace.
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS));
//		printAddressSet(as);
//		printAddressSet(programDiff.getDifferences(programDiff.getFilter(), null));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	@Test
	public void testDiffFunctionVarArgs() throws Exception {
		// 0100248f
		// 010033f6
		// 01003bed
		// 01006420
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					try {
						// 0100248f
						// 01003bed
						Function f0100248f =
							program.getFunctionManager().getFunctionAt(addr(program, "0x0100248f"));
						Function f01003bed =
							program.getFunctionManager().getFunctionAt(addr(program, "0x01003bed"));
						f0100248f.setVarArgs(true);
						f01003bed.setVarArgs(true);
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// P2 program
				int txId = program.startTransaction("Modify Program 2");
				boolean commit = false;
				try {
					try {
						// 010033f6
						// 01003bed
						Function f010033f6 =
							program.getFunctionManager().getFunctionAt(addr(program, "0x010033f6"));
						Function f01003bed =
							program.getFunctionManager().getFunctionAt(addr(program, "0x01003bed"));
						f010033f6.setVarArgs(true);
						f01003bed.setVarArgs(true);
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		p1 = mtf.getResultProgram();
		p2 = mtf.getPrivateProgram();

		programDiff = new ProgramDiff(p1, p2);
		AddressSet as = new AddressSet();
		as.addRange(addr(p1, "0x0100248f"), addr(p1, "0x0100248f"));
		as.addRange(addr(p1, "0x010033f6"), addr(p1, "0x010033f6"));
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	/**
	 * Tests that adding different tags to different functions is recognized as a difference.
	 *
	 * @throws Exception
	 */
	@Test
	public void testDiffFunctionTags1() throws Exception {
		// 0100248f
		// 010033f6
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					try {
						// 0100248f
						Function f0100248f =
							program.getFunctionManager().getFunctionAt(addr(program, "0x0100248f"));
						f0100248f.addTag("tagA");
						f0100248f.addTag("tagB");
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// P2 program
				int txId = program.startTransaction("Modify Program 2");
				boolean commit = false;
				try {
					try {
						// 010033f6
						Function f010033f6 =
							program.getFunctionManager().getFunctionAt(addr(program, "0x010033f6"));
						f010033f6.addTag("tagC");
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		p1 = mtf.getResultProgram();
		p2 = mtf.getPrivateProgram();

		programDiff = new ProgramDiff(p1, p2);
		AddressSet as = new AddressSet();
		as.addRange(addr(p1, "0x0100248f"), addr(p1, "0x0100248f"));
		as.addRange(addr(p1, "0x010033f6"), addr(p1, "0x010033f6"));
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_TAG_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	/**
	 * Tests that if we add the same tags to two different programs, they are NOT counted
	 * as being different.
	 *
	 * @throws Exception
	 */
	@Test
	public void testDiffFunctionTags2() throws Exception {
		// 0100248f
		// 010033f6
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					try {
						// 0100248f
						Function f0100248f =
							program.getFunctionManager().getFunctionAt(addr(program, "0x0100248f"));
						f0100248f.addTag("tagA");
						f0100248f.addTag("tagB");
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// P2 program
				int txId = program.startTransaction("Modify Program 2");
				boolean commit = false;
				try {
					try {
						// 0100248f
						Function f0100248f =
							program.getFunctionManager().getFunctionAt(addr(program, "0x0100248f"));
						f0100248f.addTag("tagA");
						f0100248f.addTag("tagB");
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		p1 = mtf.getResultProgram();
		p2 = mtf.getPrivateProgram();

		programDiff = new ProgramDiff(p1, p2);
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_TAG_DIFFS));
		AddressSetView as = programDiff.getDifferences(programDiff.getFilter(), null);
		assertTrue(as.isEmpty());
	}

	/**
	 * Tests that adding different tags to the same function is recognized as a difference.
	 *
	 * @throws Exception
	 */
	@Test
	public void testDiffFunctionTags3() throws Exception {
		// 0100248f
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					try {
						// 0100248f
						Function f0100248f =
							program.getFunctionManager().getFunctionAt(addr(program, "0x0100248f"));
						f0100248f.addTag("tagA");
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// P2 program
				int txId = program.startTransaction("Modify Program 2");
				boolean commit = false;
				try {
					try {
						// 0100248f
						Function f0100248f =
							program.getFunctionManager().getFunctionAt(addr(program, "0x0100248f"));
						f0100248f.addTag("tagB");
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		p1 = mtf.getResultProgram();
		p2 = mtf.getPrivateProgram();

		programDiff = new ProgramDiff(p1, p2);
		AddressSet as = new AddressSet();
		as.addRange(addr(p1, "0x0100248f"), addr(p1, "0x0100248f"));
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_TAG_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	@Test
	public void testDiffFunctionInlines() throws Exception {
		// 0100248f
		// 010033f6
		// 01003bed
		// 01006420
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					try {
						// 0100248f
						// 01003bed
						Function f0100248f =
							program.getFunctionManager().getFunctionAt(addr(program, "0x0100248f"));
						Function f01003bed =
							program.getFunctionManager().getFunctionAt(addr(program, "0x01003bed"));
						f0100248f.setInline(true);
						f01003bed.setInline(true);
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// P2 program
				int txId = program.startTransaction("Modify Program 2");
				boolean commit = false;
				try {
					try {
						// 010033f6
						// 01003bed
						Function f010033f6 =
							program.getFunctionManager().getFunctionAt(addr(program, "0x010033f6"));
						Function f01003bed =
							program.getFunctionManager().getFunctionAt(addr(program, "0x01003bed"));
						f010033f6.setInline(true);
						f01003bed.setInline(true);
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		p1 = mtf.getResultProgram();
		p2 = mtf.getPrivateProgram();

		programDiff = new ProgramDiff(p1, p2);
		AddressSet as = new AddressSet();
		as.addRange(addr(p1, "0x0100248f"), addr(p1, "0x0100248f"));
		as.addRange(addr(p1, "0x010033f6"), addr(p1, "0x010033f6"));
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	@Test
	public void testDiffFunctionNoReturns() throws Exception {
		// 0100248f
		// 010033f6
		// 01003bed
		// 01006420
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					try {
						// 0100248f
						// 01003bed
						Function f0100248f =
							program.getFunctionManager().getFunctionAt(addr(program, "0x0100248f"));
						Function f01003bed =
							program.getFunctionManager().getFunctionAt(addr(program, "0x01003bed"));
						f0100248f.setNoReturn(true);
						f01003bed.setNoReturn(true);
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// P2 program
				int txId = program.startTransaction("Modify Program 2");
				boolean commit = false;
				try {
					try {
						// 010033f6
						// 01003bed
						Function f010033f6 =
							program.getFunctionManager().getFunctionAt(addr(program, "0x010033f6"));
						Function f01003bed =
							program.getFunctionManager().getFunctionAt(addr(program, "0x01003bed"));
						f010033f6.setNoReturn(true);
						f01003bed.setNoReturn(true);
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		p1 = mtf.getResultProgram();
		p2 = mtf.getPrivateProgram();

		programDiff = new ProgramDiff(p1, p2);
		AddressSet as = new AddressSet();
		as.addRange(addr(p1, "0x0100248f"), addr(p1, "0x0100248f"));
		as.addRange(addr(p1, "0x010033f6"), addr(p1, "0x010033f6"));
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	@Test
	public void testDiffFunctionCallingConventions() throws Exception {
		// NotepadMergeListingTest_X86 has "unknown", "default", "__stdcall", "__cdecl", "__fastcall", "__thiscall".
		// 0100248f
		// 010033f6
		// 01003bed
		// 01006420

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					try {
						// 01006420 entry()
						// 010033f6 FUN_010033f6()
						// 0100248f FUN_0100248f()
						Function f01006420 =
							program.getFunctionManager().getFunctionAt(addr(program, "0x01006420"));
						Function f010033f6 =
							program.getFunctionManager().getFunctionAt(addr(program, "0x010033f6"));
						Function f0100248f =
							program.getFunctionManager().getFunctionAt(addr(program, "0x0100248f"));
						f01006420.setCallingConvention("__stdcall");
						f010033f6.setCallingConvention("__thiscall");
						f0100248f.setCallingConvention("__cdecl");
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// P2 program
				int txId = program.startTransaction("Modify Program 2");
				boolean commit = false;
				try {
					try {
						// 01003bed FUN_01003bed()
						// 010033f6 FUN_010033f6()
						// 0100248f FUN_0100248f()
						Function f01003bed =
							program.getFunctionManager().getFunctionAt(addr(program, "0x01003bed"));
						Function f010033f6 =
							program.getFunctionManager().getFunctionAt(addr(program, "0x010033f6"));
						Function f0100248f =
							program.getFunctionManager().getFunctionAt(addr(program, "0x0100248f"));
						f01003bed.setCallingConvention("__cdecl");
						f010033f6.setCallingConvention("__thiscall");
						f0100248f.setCallingConvention("__fastcall");
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		p1 = mtf.getResultProgram();
		p2 = mtf.getPrivateProgram();

		programDiff = new ProgramDiff(p1, p2);
		AddressSet as = new AddressSet();
		// 01006420 entry()
		// 01003bed FUN_01001ae3()
		// 010033f6 FUN_010021f3()
		// 0100248f FUN_0100248f()
		as.addRange(addr(p1, "0x01006420"), addr(p1, "0x01006420"));
		as.addRange(addr(p1, "0x01003bed"), addr(p1, "0x01003bed"));
		as.addRange(addr(p1, "0x0100248f"), addr(p1, "0x0100248f"));
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	@Test
	public void testDiffOverlaySymbols() throws Exception {
		mtf.initialize("overlayCalc", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					SymbolTable st = program.getSymbolTable();
					try {
						st.createLabel(addr(program, "TextOverlay::01001630"), "OVL1630",
							SourceType.USER_DEFINED);
						st.createLabel(addr(program, "TextOverlay::01001646"), "OVL1646",
							SourceType.USER_DEFINED);
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// P2 program
				int txId = program.startTransaction("Modify Program 2");
				boolean commit = false;
				try {
					SymbolTable st = program.getSymbolTable();
					try {
						st.createLabel(addr(program, "TextOverlay::01001639"), "OVL1639",
							SourceType.USER_DEFINED);
						st.createLabel(addr(program, "TextOverlay::01001646"), "OVL1646",
							SourceType.USER_DEFINED);
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		p1 = mtf.getResultProgram();
		p2 = mtf.getPrivateProgram();

		programDiff = new ProgramDiff(p1, p2);
		AddressSet as = new AddressSet();
		as.addRange(addr(p1, "TextOverlay::01001630"), addr(p1, "TextOverlay::01001630"));
		as.addRange(addr(p1, "TextOverlay::01001639"), addr(p1, "TextOverlay::01001639"));
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	@Test
	public void testDiffOverlaysSame() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					try {
						Memory memory = program.getMemory();
						memory.createInitializedBlock("Foo", addr(program, "0x01000000"), 0x200L,
							(byte) 0x0, null, true);
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// P2 program
				int txId = program.startTransaction("Modify Program 2");
				boolean commit = false;
				try {
					try {
						Memory memory = program.getMemory();
						memory.createInitializedBlock("Foo", addr(program, "0x01000000"), 0x200L,
							(byte) 0x0, null, true);
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		p1 = mtf.getResultProgram();
		p2 = mtf.getPrivateProgram();

		programDiff = new ProgramDiff(p1, p2);
		AddressSet as = new AddressSet();
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.ALL_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	@Test
	public void testDiffOverlaysDiffNames() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					try {
						Memory memory = program.getMemory();
						memory.createInitializedBlock("Foo", addr(program, "0x01000000"), 0x200L,
							(byte) 0x0, null, true);
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// P2 program
				int txId = program.startTransaction("Modify Program 2");
				boolean commit = false;
				try {
					try {
						Memory memory = program.getMemory();
						memory.createInitializedBlock("Bar", addr(program, "0x01000000"), 0x200L,
							(byte) 0x0, null, true);
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		p1 = mtf.getResultProgram();
		p2 = mtf.getPrivateProgram();

		programDiff = new ProgramDiff(p1, p2);
		AddressSet as = new AddressSet();
		as.addRange(addr(p1, "Foo:0x01000000"), addr(p1, "Foo:0x010001ff"));
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.ALL_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	@Test
	public void testDiffOfSameOverlaysWithChanges() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					try {
						Memory memory = program.getMemory();
						memory.createInitializedBlock("Foo", addr(program, "0x01000000"), 0x200L,
							(byte) 0x0, null, true);

						SymbolTable st = program.getSymbolTable();
						Namespace globalNamespace = program.getGlobalNamespace();
						st.createLabel(addr(program, "Foo:0x01000030"), "Sample0030",
							globalNamespace, SourceType.USER_DEFINED);
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// P2 program
				int txId = program.startTransaction("Modify Program 2");
				boolean commit = false;
				try {
					try {
						Memory memory = program.getMemory();
						memory.createInitializedBlock("Foo", addr(program, "0x01000000"), 0x200L,
							(byte) 0x0, null, true);

						SymbolTable st = program.getSymbolTable();
						Namespace globalNamespace = program.getGlobalNamespace();
						st.createLabel(addr(program, "Foo:0x01000050"), "Other0050",
							globalNamespace, SourceType.USER_DEFINED);
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		p1 = mtf.getResultProgram();
		p2 = mtf.getPrivateProgram();

		programDiff = new ProgramDiff(p1, p2);
		AddressSet as = new AddressSet();
		as.addRange(addr(p1, "Foo:0x01000030"), addr(p1, "Foo:0x01000030"));
		as.addRange(addr(p1, "Foo:0x01000050"), addr(p1, "Foo:0x01000050"));
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.ALL_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	@Test
	public void testDiffOfOverlapOverlaysWithChanges() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					try {
						Memory memory = program.getMemory();
						memory.createInitializedBlock("Foo", addr(program, "0x01000000"), 0x180L,
							(byte) 0x0, null, true);

						SymbolTable st = program.getSymbolTable();
						Namespace globalNamespace = program.getGlobalNamespace();
						st.createLabel(addr(program, "Foo:0x01000030"), "Sample0030",
							globalNamespace, SourceType.USER_DEFINED);
						st.createLabel(addr(program, "Foo:0x01000079"), "Sample0079",
							globalNamespace, SourceType.USER_DEFINED);
						st.createLabel(addr(program, "Foo:0x0100017f"), "Sample017f",
							globalNamespace, SourceType.USER_DEFINED);
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// P2 program
				int txId = program.startTransaction("Modify Program 2");
				boolean commit = false;
				try {
					try {
						Memory memory = program.getMemory();
						memory.createInitializedBlock("Foo", addr(program, "0x01000080"), 0x180L,
							(byte) 0x0, null, true);

						SymbolTable st = program.getSymbolTable();
						Namespace globalNamespace = program.getGlobalNamespace();
						st.createLabel(addr(program, "Foo:0x01000080"), "Other0080",
							globalNamespace, SourceType.USER_DEFINED);
						st.createLabel(addr(program, "Foo:0x01000180"), "Other0180",
							globalNamespace, SourceType.USER_DEFINED);
						st.createLabel(addr(program, "Foo:0x01000200"), "Other0200",
							globalNamespace, SourceType.USER_DEFINED);
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		p1 = mtf.getResultProgram();
		p2 = mtf.getPrivateProgram();

		// No addresses should be considered to be in common for the overlays.
		programDiff = new ProgramDiff(p1, p2);
		AddressSet as = new AddressSet();
		as.addRange(addr(p1, "Foo:0x01000000"), addr(p1, "Foo:0x0100017f"));
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.ALL_DIFFS));
		AddressSetView diffs = programDiff.getDifferences(programDiff.getFilter(), null);
		assertEquals(as, diffs);
	}

	@Test
	public void testSameRefSource() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					try {
						ReferenceManager refMgr = program.getReferenceManager();
						refMgr.addMemoryReference(addr(program, "0x01001e81"),
							addr(program, "0x01001ea0"), RefType.DATA, SourceType.USER_DEFINED, 0);
						refMgr.addMemoryReference(addr(program, "0x01001ea0"),
							addr(program, "0x01001eba"), RefType.DATA, SourceType.IMPORTED, 0);
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// P2 program
				int txId = program.startTransaction("Modify Program 2");
				boolean commit = false;
				try {
					try {
						ReferenceManager refMgr = program.getReferenceManager();
						refMgr.addMemoryReference(addr(program, "0x01001e81"),
							addr(program, "0x01001ea0"), RefType.DATA, SourceType.USER_DEFINED, 0);
						refMgr.addMemoryReference(addr(program, "0x01001ea0"),
							addr(program, "0x01001eba"), RefType.DATA, SourceType.IMPORTED, 0);
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		p1 = mtf.getResultProgram();
		p2 = mtf.getPrivateProgram();

		programDiff = new ProgramDiff(p1, p2);
		AddressSet as = new AddressSet();
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	@Test
	public void testDiffRefSource() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					try {
						ReferenceManager refMgr = program.getReferenceManager();
						refMgr.addMemoryReference(addr(program, "0x01001e81"),
							addr(program, "0x01001ea0"), RefType.DATA, SourceType.USER_DEFINED, 0);
						refMgr.addMemoryReference(addr(program, "0x01001ea0"),
							addr(program, "0x01001eba"), RefType.DATA, SourceType.IMPORTED, 0);
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// P2 program
				int txId = program.startTransaction("Modify Program 2");
				boolean commit = false;
				try {
					try {
						ReferenceManager refMgr = program.getReferenceManager();
						refMgr.addMemoryReference(addr(program, "0x01001e81"),
							addr(program, "0x01001ea0"), RefType.DATA, SourceType.IMPORTED, 0);
						refMgr.addMemoryReference(addr(program, "0x01001ea0"),
							addr(program, "0x01001eba"), RefType.DATA, SourceType.ANALYSIS, 0);
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		p1 = mtf.getResultProgram();
		p2 = mtf.getPrivateProgram();

		programDiff = new ProgramDiff(p1, p2);
		AddressSet as = new AddressSet();
		// For now we no longer want to detect source type differences since they can't be changed anyway.
//		as.addRange(addr(p1, "0x01001e81"), addr(p1, "0x01001e82"));
//		as.addRange(addr(p1, "0x01001ea0"), addr(p1, "0x01001ea1"));
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	@Test
	public void testDiffForcedIndirectParameter() throws Exception {

		mtf.initialize("DiffTestPgm1_X86_64", new ProgramModifierListener() {

			// should detect diff on parameter data type.

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x1000");
					Parameter parameter1 =
						new ParameterImpl("stuff", new ByteDataType(), 4, program);
					func.addParameter(parameter1, SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
				Function func = getFunction(program, "0x1000");
				assertEquals("void bob(byte stuff)", func.getPrototypeString(true, false));
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// Forced indirect for the return.
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Structure struct = new StructureDataType("struct", 20);
					Function func = getFunction(program, "0x1000");
					Parameter parameter1 = new ParameterImpl("stuff", struct, 4, program);
					func.addParameter(parameter1, SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
				Function func = getFunction(program, "0x1000");
				assertEquals("void bob(struct stuff)", func.getPrototypeString(true, false));
				Parameter parameter = func.getParameter(0);
				assertEquals("[struct * stuff@RCX:8 (ptr)]", parameter.toString());
			}
		});

		p1 = mtf.getResultProgram();
		p2 = mtf.getPrivateProgram();

		programDiff = new ProgramDiff(p1, p2);
		AddressSet as = new AddressSet();
		as.addRange(addr(p1, "0x00001000"), addr(p1, "0x00001000"));
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	@Test
	public void testDiffForcedIndirectOnReturnVsAutoParam() throws Exception {

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			// should detect diff on return type and jim vs. bob parameter name, with return ptr auto-param

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x1002249");
					func.getParameter(1).setName("jim", SourceType.USER_DEFINED);
					func.setReturn(Undefined4DataType.dataType, VariableStorage.UNASSIGNED_STORAGE,
						SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// Forced indirect for the return.
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Structure struct = new StructureDataType("struct", 20);
					Function func = getFunction(program, "0x1002249");
					func.getParameter(1).setName("bob", SourceType.USER_DEFINED);
					// trigger injection of auto-param return pointer as parameter-1 (bob is now parameter-2)
					func.setReturn(struct, VariableStorage.UNASSIGNED_STORAGE,
						SourceType.USER_DEFINED);
					func.setCallingConvention(CompilerSpec.CALLING_CONVENTION_stdcall);
					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		p1 = mtf.getResultProgram();
		p2 = mtf.getPrivateProgram();

		programDiff = new ProgramDiff(p1, p2);
		AddressSet as = new AddressSet();
		as.addRange(addr(p1, "0x1002249"), addr(p1, "0x1002249"));
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	@Test
	public void testDiffOverlayOrder() throws Exception {
		mtf.initialize("overlayCalc", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					SymbolTable st = program.getSymbolTable();
					try {
						program.getMemory().createInitializedBlock("SomeOverlay",
							addr(program, "0x01001630"), 0x200, (byte) 0, TaskMonitor.DUMMY, true);
						program.getMemory().createInitializedBlock("OtherOverlay",
							addr(program, "0x01001630"), 0x300, (byte) 0, TaskMonitor.DUMMY, true);
						st.createLabel(addr(program, "SomeOverlay::01001630"), "OVL1630",
							SourceType.USER_DEFINED);
						st.createLabel(addr(program, "OtherOverlay::01001866"), "OVL1866",
							SourceType.USER_DEFINED);
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// P2 program
				int txId = program.startTransaction("Modify Program 2");
				boolean commit = false;
				try {
					SymbolTable st = program.getSymbolTable();
					try {
						program.getMemory().createInitializedBlock("OtherOverlay",
							addr(program, "0x01001630"), 0x200, (byte) 0, TaskMonitor.DUMMY, true);
						program.getMemory().createInitializedBlock("SomeOverlay",
							addr(program, "0x01001630"), 0x300, (byte) 0, TaskMonitor.DUMMY, true);
						st.createLabel(addr(program, "SomeOverlay::01001889"), "OVL1889",
							SourceType.USER_DEFINED);
						st.createLabel(addr(program, "OtherOverlay::01001646"), "OVL1646",
							SourceType.USER_DEFINED);
					}
					catch (Exception e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		p1 = mtf.getResultProgram();
		p2 = mtf.getPrivateProgram();

		programDiff = new ProgramDiff(p1, p2);
		AddressSet as = new AddressSet();
		as.addRange(addr(p1, "SomeOverlay::01001630"), addr(p1, "SomeOverlay::01001630"));
		// Diff won't detect SomeOverlay::01001889 because it isn't in p1.
		as.addRange(addr(p1, "OtherOverlay::01001646"), addr(p1, "OtherOverlay::01001646"));
		as.addRange(addr(p1, "OtherOverlay::01001866"), addr(p1, "OtherOverlay::01001866"));
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

//	private void printAddressSet(AddressSetView diffAs) {
//		System.out.println("=====");
//		for (AddressRange addressRange : diffAs) {
//			System.out.println("[" + addressRange.getMinAddress() + "," +
//				addressRange.getMaxAddress() + "]");
//		}
//		System.out.println("-----");
//	}

}
