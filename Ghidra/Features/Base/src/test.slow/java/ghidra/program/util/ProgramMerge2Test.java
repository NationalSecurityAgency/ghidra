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

import java.util.*;

import org.junit.*;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.database.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * <CODE>ProgramMerge2Test</CODE> tests the <CODE>ProgramMerge</CODE> class
 * to verify it correctly merges various types of program differences.
 * The tests modify copies of the same program to cause differences
 * between these two programs, which can then be merged.
 */
public class ProgramMerge2Test extends AbstractGhidraHeadedIntegrationTest {

	protected MergeTestFacilitator mtf;
	protected Program originalProgram;
	protected Program latestProgram;
	protected Program myProgram;
	protected Program resultProgram;
	private ProgramMergeManager programMerge;
	Program p1;
	Program p2;
	int txId1;
	int txId2;

	public ProgramMerge2Test() {
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

	private Address addr(Program p, String addrString) {
		return AddressEvaluator.evaluate(p, addrString);
	}

	private void createDataReference(Program pgm, Address fromAddr, Address toAddr) {
		ReferenceManager refMgr = pgm.getReferenceManager();
		refMgr.addMemoryReference(fromAddr, toAddr, RefType.DATA, SourceType.USER_DEFINED, 0);
	}

	@Test
	public void testReplaceWithGlobalLabel() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
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

			@Override
			public void modifyPrivate(ProgramDB program) {
				// P2 program
				int txId = program.startTransaction("Modify Program 2");
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
		});

		p1 = mtf.getResultProgram();
		p2 = mtf.getPrivateProgram();

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x10058f6"), addr(p1, "0x10058fa"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.SYMBOLS, ProgramMergeFilter.REPLACE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x10058f7"), addr(p1, "0x10058f7"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x10058f7"), addr(p1, "0x10058f8"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			assertEquals(new AddressSet(), programMerge.getFilteredDifferences());

			SymbolTable st = p1.getSymbolTable();
			Symbol[] syms = st.getSymbols(addr(p1, "0x010058f7"));
			assertEquals(1, syms.length);
			assertEquals("MY.DLL_SampleLabel", syms[0].getName());
			assertEquals("Global", syms[0].getParentNamespace().getName());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testReplaceNamespaceLabels() throws Exception {
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

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x10058f6"), addr(p1, "0x10058fa"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.SYMBOLS, ProgramMergeFilter.REPLACE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x10058f7"), addr(p1, "0x10058f7"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x10058f7"), addr(p1, "0x10058f8"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			assertEquals(new AddressSet(), programMerge.getFilteredDifferences());

			SymbolTable st = p1.getSymbolTable();
			Symbol[] syms = st.getSymbols(addr(p1, "0x010058f7"));
			assertEquals(1, syms.length);
			assertEquals("SampleLabel", syms[0].getName());
			assertEquals("MY.DLL", syms[0].getParentNamespace().getName());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testMergeNamespaceLabels() throws Exception {
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

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x10058f6"), addr(p1, "0x10058fa"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.SYMBOLS, ProgramMergeFilter.MERGE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x10058f7"), addr(p1, "0x10058f7"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x10058f7"), addr(p1, "0x10058f8"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			SymbolTable st = p1.getSymbolTable();
			Symbol[] syms = st.getSymbols(addr(p1, "0x010058f7"));
			assertEquals(2, syms.length);
			assertEquals("MY.DLL_SampleLabel", syms[0].getName());
			assertEquals("Global", syms[0].getParentNamespace().getName());
			assertEquals(true, syms[0].isPrimary());
			assertEquals("SampleLabel", syms[1].getName());
			assertEquals("MY.DLL", syms[1].getParentNamespace().getName());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testMergeNamespaceLabelsSetPrimary() throws Exception {
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

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x10058f6"), addr(p1, "0x10058fa"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS));
			programMerge.setMergeFilter(new ProgramMergeFilter(
				ProgramMergeFilter.SYMBOLS | ProgramMergeFilter.PRIMARY_SYMBOL,
				ProgramMergeFilter.MERGE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x10058f7"), addr(p1, "0x10058f7"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x10058f7"), addr(p1, "0x10058f8"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			SymbolTable st = p1.getSymbolTable();
			Symbol[] syms = st.getSymbols(addr(p1, "0x010058f7"));
			assertEquals(2, syms.length);
			assertEquals("SampleLabel", syms[0].getName());
			assertEquals("MY.DLL", syms[0].getParentNamespace().getName());
			assertEquals(true, syms[0].isPrimary());
			assertEquals("MY.DLL_SampleLabel", syms[1].getName());
			assertEquals("Global", syms[1].getParentNamespace().getName());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testReplaceSymbolAbsorbByFunction() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// P2 program
				int txId = program.startTransaction("Modify Program 2");
				boolean commit = false;
				try {
					FunctionManager functionMgr = program.getFunctionManager();
					SymbolTable st = program.getSymbolTable();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01004c1d"));
						f.setName("SampleFunction", SourceType.USER_DEFINED);
						Namespace namespace = st.createNameSpace(program.getGlobalNamespace(),
							"MY.DLL", SourceType.USER_DEFINED);
						f.setParentNamespace(namespace);
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

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x01001a00"), addr(p1, "0x01006500"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.SYMBOLS, ProgramMergeFilter.REPLACE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x1004c1d"), addr(p1, "0x01004c1d"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x1004c1d"), addr(p1, "0x1004c1d"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

//			assertEquals(new AddressSet(p1.getAddressFactory()),
//			             programMerge.getFilteredDifferences());

			SymbolTable st = p1.getSymbolTable();
			Symbol[] syms = st.getSymbols(addr(p1, "0x1004c1d"));
			assertEquals(1, syms.length);
			assertEquals("SampleFunction", syms[0].getName());
			assertEquals("MY.DLL", syms[0].getParentNamespace().getName());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testReplaceDefaultFunctionSymbolWithNamespace() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// P2 program
				int txId = program.startTransaction("Modify Program 2");
				boolean commit = false;
				try {
					FunctionManager functionMgr = program.getFunctionManager();
					SymbolTable st = program.getSymbolTable();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01004c1d"));
						f.setName("SampleFunction", SourceType.USER_DEFINED);
						Namespace namespace = st.createNameSpace(program.getGlobalNamespace(),
							"MY.DLL", SourceType.USER_DEFINED);
						f.setParentNamespace(namespace);
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

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x01001a00"), addr(p1, "0x01006500"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x1004c1d"), addr(p1, "0x01004c1d"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x1004c1d"), addr(p1, "0x1004c1d"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			assertEquals(new AddressSet(), programMerge.getFilteredDifferences());

			SymbolTable st = p1.getSymbolTable();
			Symbol[] syms = st.getSymbols(addr(p1, "0x1004c1d"));
			assertEquals(1, syms.length);
			assertEquals("SampleFunction", syms[0].getName());
			assertEquals("MY.DLL", syms[0].getParentNamespace().getName());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testReplaceFunction() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					Namespace namespace = program.getGlobalNamespace();
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01002cf5"));
						f.setName("MY.DLL_SampleLabel", SourceType.USER_DEFINED);
						f.setParentNamespace(namespace);
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
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						namespace = st.createNameSpace(program.getGlobalNamespace(), "MY.DLL",
							SourceType.USER_DEFINED);
						Function f = functionMgr.getFunctionAt(addr(program, "0x01002cf5"));
						f.setName("SampleLabel", SourceType.USER_DEFINED);
						f.setParentNamespace(namespace);
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

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x01001a00"), addr(p1, "0x01006500"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(
				ProgramDiffFilter.SYMBOL_DIFFS | ProgramDiffFilter.FUNCTION_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x01002cf5"), addr(p1, "0x1002cf5"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x1002cf5"), addr(p1, "0x1002cf5"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			assertEquals(new AddressSet(), programMerge.getFilteredDifferences());

			SymbolTable st = p1.getSymbolTable();
			Symbol[] syms = st.getSymbols(addr(p1, "0x1002cf5"));
			assertEquals(1, syms.length);
			assertEquals("SampleLabel", syms[0].getName());
			assertEquals("MY.DLL", syms[0].getParentNamespace().getName());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testFunctionReplaceOfNothingWithNamedFunctionInNamespace() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// P2 program
				int txId = program.startTransaction("Modify Program 2");
				boolean commit = false;
				try {
					SymbolTable st = program.getSymbolTable();
					Namespace namespace;
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Address entry = addr(program, "0x0100299e");
						namespace = st.createNameSpace(program.getGlobalNamespace(), "MY.DLL",
							SourceType.USER_DEFINED);
						CreateFunctionCmd cmd = new CreateFunctionCmd(entry);
						cmd.applyTo(program);
						Function f = functionMgr.getFunctionAt(entry);
						f.setName("SampleLabel", SourceType.USER_DEFINED);
						f.setParentNamespace(namespace);
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

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x1002998"), addr(p1, "0x1002a0c"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x0100299e"), addr(p1, "0x0100299e"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x0100299e"), addr(p1, "0x0100299e"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			// P1 should now have function in namespace and no diffs.
			assertEquals(new AddressSet(), programMerge.getFilteredDifferences());

			Function function = p1.getFunctionManager().getFunctionAt(addr(p1, "0x0100299e"));
			assertNotNull(function);
			assertEquals("MY.DLL::SampleLabel", function.getName(true));

			SymbolTable st = p1.getSymbolTable();
			Symbol[] syms = st.getSymbols(addr(p1, "0x0100299e"));
			assertEquals(1, syms.length);
			assertEquals("SampleLabel", syms[0].getName());
			assertEquals(SymbolType.FUNCTION, syms[0].getSymbolType());
			assertEquals("MY.DLL", syms[0].getParentNamespace().getName());
			assertEquals(SymbolType.NAMESPACE,
				syms[0].getParentNamespace().getSymbol().getSymbolType());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testFunctionReplaceOfNamedFunctionInNamespaceWithNothing() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					SymbolTable st = program.getSymbolTable();
					Namespace namespace;
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Address entry = addr(program, "0x0100299e");
						namespace = st.createNameSpace(program.getGlobalNamespace(), "MY.DLL",
							SourceType.USER_DEFINED);
						CreateFunctionCmd cmd = new CreateFunctionCmd(entry);
						cmd.applyTo(program);
						Function f = functionMgr.getFunctionAt(entry);
						f.setName("SampleLabel", SourceType.USER_DEFINED);
						f.setParentNamespace(namespace);
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
			}
		});

		p1 = mtf.getResultProgram();
		p2 = mtf.getPrivateProgram();

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x1002998"), addr(p1, "0x1002a0c"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x0100299e"), addr(p1, "0x0100299e"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x0100299e"), addr(p1, "0x0100299e"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			// P1 should now have a label with the old function name and a diff.
			assertEquals(new AddressSet(), programMerge.getFilteredDifferences());

			Function function = p1.getFunctionManager().getFunctionAt(addr(p1, "0x0100299e"));
			assertNull(function);

			SymbolTable st = p1.getSymbolTable();
			Symbol[] syms = st.getSymbols(addr(p1, "0x0100299e"));
			assertEquals(1, syms.length);
			assertEquals("SampleLabel", syms[0].getName());
			assertEquals(SymbolType.LABEL, syms[0].getSymbolType());
			assertEquals("MY.DLL", syms[0].getParentNamespace().getName());
			assertEquals(SymbolType.NAMESPACE,
				syms[0].getParentNamespace().getSymbol().getSymbolType());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testFunctionAndSymbolReplaceOfFunctionWithFunctionInNamespace() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01002cf5"));
						f.setName("MY.DLL_SampleLabel", SourceType.IMPORTED);
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
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						namespace = st.createNameSpace(program.getGlobalNamespace(), "MY.DLL",
							SourceType.USER_DEFINED);
						Function f = functionMgr.getFunctionAt(addr(program, "0x01002cf5"));
						f.setName("SampleLabel", SourceType.IMPORTED);
						f.setParentNamespace(namespace);
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

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x01001a00"), addr(p1, "0x01006500"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(
				ProgramDiffFilter.FUNCTION_DIFFS | ProgramDiffFilter.SYMBOL_DIFFS));
			ProgramMergeFilter filter = new ProgramMergeFilter();
			filter.setFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE);
			filter.setFilter(ProgramMergeFilter.SYMBOLS, ProgramMergeFilter.REPLACE);
			programMerge.setMergeFilter(filter);
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x01002cf5"), addr(p1, "0x01002cf5"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x01002cf5"), addr(p1, "0x01002cf5"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			// P1 should now have function in namespace and no diffs.
			assertEquals(new AddressSet(), programMerge.getFilteredDifferences());

			Function function = p1.getFunctionManager().getFunctionAt(addr(p1, "0x01002cf5"));
			assertNotNull(function);
			assertEquals("MY.DLL::SampleLabel", function.getName(true));

			SymbolTable st = p1.getSymbolTable();
			Symbol[] syms = st.getSymbols(addr(p1, "0x01002cf5"));
			assertEquals(1, syms.length);
			assertEquals("SampleLabel", syms[0].getName());
			assertEquals(SymbolType.FUNCTION, syms[0].getSymbolType());
			assertEquals("MY.DLL", syms[0].getParentNamespace().getName());
			assertEquals(SymbolType.NAMESPACE,
				syms[0].getParentNamespace().getSymbol().getSymbolType());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testFunctionAndSymbolMergeOfFunctionWithFunctionInNamespace() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01002cf5"));
						f.setName("MY.DLL_SampleLabel", SourceType.IMPORTED);
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
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						namespace = st.createNameSpace(program.getGlobalNamespace(), "MY.DLL",
							SourceType.USER_DEFINED);
						Function f = functionMgr.getFunctionAt(addr(program, "0x01002cf5"));
						f.setName("SampleLabel", SourceType.IMPORTED);
						f.setParentNamespace(namespace);
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

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x01001a00"), addr(p1, "0x01006500"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(
				ProgramDiffFilter.FUNCTION_DIFFS | ProgramDiffFilter.SYMBOL_DIFFS));
			ProgramMergeFilter filter = new ProgramMergeFilter();
			filter.setFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE);
			filter.setFilter(ProgramMergeFilter.SYMBOLS, ProgramMergeFilter.MERGE);
			filter.setFilter(ProgramMergeFilter.PRIMARY_SYMBOL, ProgramMergeFilter.REPLACE);
			programMerge.setMergeFilter(filter);
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x01002cf5"), addr(p1, "0x01002cf5"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x01002cf5"), addr(p1, "0x01002cf5"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			// P1 should now have function in namespace and no diffs.
			AddressSet diffSet = new AddressSet(addr(p1, "0x01002cf5"), addr(p1, "0x01002cf5"));
			assertEquals(diffSet, programMerge.getFilteredDifferences());

			Function function = p1.getFunctionManager().getFunctionAt(addr(p1, "0x01002cf5"));
			assertNotNull(function);
			assertEquals("MY.DLL::SampleLabel", function.getName(true));

			SymbolTable st = p1.getSymbolTable();
			Symbol[] syms = st.getSymbols(addr(p1, "0x01002cf5"));
			assertEquals(2, syms.length);
			assertEquals("SampleLabel", syms[0].getName());
			assertEquals(SymbolType.FUNCTION, syms[0].getSymbolType());
			assertEquals("MY.DLL", syms[0].getParentNamespace().getName());
			assertEquals(SymbolType.NAMESPACE,
				syms[0].getParentNamespace().getSymbol().getSymbolType());
			assertEquals("MY.DLL_SampleLabel", syms[1].getName());
			assertEquals(SymbolType.LABEL, syms[1].getSymbolType());
			assertEquals("Global", syms[1].getParentNamespace().getName());
			assertEquals(SymbolType.GLOBAL,
				syms[1].getParentNamespace().getSymbol().getSymbolType());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testFunctionAndSymbolMergePrimaryOfFunctionWithFunctionInNamespace()
			throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01002cf5"));
						f.setName("MY.DLL_SampleLabel", SourceType.IMPORTED);
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
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						namespace = st.createNameSpace(program.getGlobalNamespace(), "MY.DLL",
							SourceType.USER_DEFINED);
						Function f = functionMgr.getFunctionAt(addr(program, "0x01002cf5"));
						f.setName("SampleLabel", SourceType.IMPORTED);
						f.setParentNamespace(namespace);
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

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x01001a00"), addr(p1, "0x01006500"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(
				ProgramDiffFilter.FUNCTION_DIFFS | ProgramDiffFilter.SYMBOL_DIFFS));
			ProgramMergeFilter filter = new ProgramMergeFilter();
			filter.setFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE);
			filter.setFilter(ProgramMergeFilter.SYMBOLS, ProgramMergeFilter.MERGE);
			filter.setFilter(ProgramMergeFilter.PRIMARY_SYMBOL, ProgramMergeFilter.MERGE);
			programMerge.setMergeFilter(filter);
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x01002cf5"), addr(p1, "0x01002cf5"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x01002cf5"), addr(p1, "0x01002cf5"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			// P1 should now have function in namespace and no diffs.
			AddressSet diffSet = new AddressSet(addr(p1, "0x01002cf5"), addr(p1, "0x01002cf5"));
			assertEquals(diffSet, programMerge.getFilteredDifferences());

			Function function = p1.getFunctionManager().getFunctionAt(addr(p1, "0x01002cf5"));
			assertNotNull(function);
			assertEquals("MY.DLL::SampleLabel", function.getName(true));

			SymbolTable st = p1.getSymbolTable();
			Symbol[] syms = st.getSymbols(addr(p1, "0x01002cf5"));
			assertEquals(2, syms.length);
			assertEquals("SampleLabel", syms[0].getName());
			assertEquals(SymbolType.FUNCTION, syms[0].getSymbolType());
			assertEquals("MY.DLL", syms[0].getParentNamespace().getName());
			assertEquals(SymbolType.NAMESPACE,
				syms[0].getParentNamespace().getSymbol().getSymbolType());
			assertEquals("MY.DLL_SampleLabel", syms[1].getName());
			assertEquals(SymbolType.LABEL, syms[1].getSymbolType());
			assertEquals("Global", syms[1].getParentNamespace().getName());
			assertEquals(SymbolType.GLOBAL,
				syms[1].getParentNamespace().getSymbol().getSymbolType());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testSymbolReplaceOfFunctionWithFunctionInNamespace() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01002cf5"));
						f.setName("MY.DLL_SampleLabel", SourceType.IMPORTED);
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
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						namespace = st.createNameSpace(program.getGlobalNamespace(), "MY.DLL",
							SourceType.USER_DEFINED);
						Function f = functionMgr.getFunctionAt(addr(program, "0x01002cf5"));
						f.setName("SampleLabel", SourceType.IMPORTED);
						f.setParentNamespace(namespace);
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

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x01001a00"), addr(p1, "0x01006500"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS));
			ProgramMergeFilter filter = new ProgramMergeFilter();
			filter.setFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.IGNORE);
			filter.setFilter(ProgramMergeFilter.SYMBOLS, ProgramMergeFilter.REPLACE);
			filter.setFilter(ProgramMergeFilter.PRIMARY_SYMBOL, ProgramMergeFilter.IGNORE);
			programMerge.setMergeFilter(filter);
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x01002cf5"), addr(p1, "0x01002cf5"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x01002cf5"), addr(p1, "0x01002cf5"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			// P1 should now have function in namespace and no diffs.
			assertEquals(new AddressSet(), programMerge.getFilteredDifferences());

			Function function = p1.getFunctionManager().getFunctionAt(addr(p1, "0x01002cf5"));
			assertNotNull(function);
			assertEquals("MY.DLL::SampleLabel", function.getName(true));

			SymbolTable st = p1.getSymbolTable();
			Symbol[] syms = st.getSymbols(addr(p1, "0x01002cf5"));
			assertEquals(1, syms.length);
			assertEquals("SampleLabel", syms[0].getName());
			assertEquals(SymbolType.FUNCTION, syms[0].getSymbolType());
			assertEquals("MY.DLL", syms[0].getParentNamespace().getName());
			assertEquals(SymbolType.NAMESPACE,
				syms[0].getParentNamespace().getSymbol().getSymbolType());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testSymbolMergeOfFunctionWithFunctionInNamespace() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01002cf5"));
						f.setName("MY.DLL_SampleLabel", SourceType.IMPORTED);
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
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						namespace = st.createNameSpace(program.getGlobalNamespace(), "MY.DLL",
							SourceType.USER_DEFINED);
						Function f = functionMgr.getFunctionAt(addr(program, "0x01002cf5"));
						f.setName("SampleLabel", SourceType.IMPORTED);
						f.setParentNamespace(namespace);
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

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x01001a00"), addr(p1, "0x01006500"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS));
			ProgramMergeFilter filter = new ProgramMergeFilter();
			filter.setFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.IGNORE);
			filter.setFilter(ProgramMergeFilter.SYMBOLS, ProgramMergeFilter.MERGE);
			filter.setFilter(ProgramMergeFilter.PRIMARY_SYMBOL, ProgramMergeFilter.IGNORE);
			programMerge.setMergeFilter(filter);
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x01002cf5"), addr(p1, "0x01002cf5"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x01002cf5"), addr(p1, "0x01002cf5"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			// P1 should now have function in namespace and no diffs.
			AddressSet diffSet = new AddressSet(addr(p1, "0x01002cf5"), addr(p1, "0x01002cf5"));
			assertEquals(diffSet, programMerge.getFilteredDifferences());

			Function function = p1.getFunctionManager().getFunctionAt(addr(p1, "0x01002cf5"));
			assertNotNull(function);
			assertEquals("MY.DLL_SampleLabel", function.getName(true));

			SymbolTable st = p1.getSymbolTable();
			Symbol[] syms = st.getSymbols(addr(p1, "0x01002cf5"));
			assertEquals(2, syms.length);
			assertEquals("MY.DLL_SampleLabel", syms[0].getName());
			assertEquals(SymbolType.FUNCTION, syms[0].getSymbolType());
			assertEquals("Global", syms[0].getParentNamespace().getName());
			assertEquals(SymbolType.GLOBAL,
				syms[0].getParentNamespace().getSymbol().getSymbolType());
			assertEquals("SampleLabel", syms[1].getName());
			assertEquals(SymbolType.LABEL, syms[1].getSymbolType());
			assertEquals("MY.DLL", syms[1].getParentNamespace().getName());
			assertEquals(SymbolType.NAMESPACE,
				syms[1].getParentNamespace().getSymbol().getSymbolType());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testSymbolMergePrimaryOfFunctionWithFunctionInNamespace() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01002cf5"));
						f.setName("MY.DLL_SampleLabel", SourceType.IMPORTED);
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
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						namespace = st.createNameSpace(program.getGlobalNamespace(), "MY.DLL",
							SourceType.USER_DEFINED);
						Function f = functionMgr.getFunctionAt(addr(program, "0x01002cf5"));
						f.setName("SampleLabel", SourceType.IMPORTED);
						f.setParentNamespace(namespace);
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

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x01001a00"), addr(p1, "0x01006500"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS));
			ProgramMergeFilter filter = new ProgramMergeFilter();
			filter.setFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.IGNORE);
			filter.setFilter(ProgramMergeFilter.SYMBOLS, ProgramMergeFilter.MERGE);
			filter.setFilter(ProgramMergeFilter.PRIMARY_SYMBOL, ProgramMergeFilter.REPLACE);
			programMerge.setMergeFilter(filter);
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x01002cf5"), addr(p1, "0x01002cf5"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x01002cf5"), addr(p1, "0x01002cf5"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			// P1 should now have function in namespace and no diffs.
			AddressSet diffSet = new AddressSet(addr(p1, "0x01002cf5"), addr(p1, "0x01002cf5"));
			assertEquals(diffSet, programMerge.getFilteredDifferences());

			Function function = p1.getFunctionManager().getFunctionAt(addr(p1, "0x01002cf5"));
			assertNotNull(function);
			assertEquals("MY.DLL::SampleLabel", function.getName(true));

			SymbolTable st = p1.getSymbolTable();
			Symbol[] syms = st.getSymbols(addr(p1, "0x01002cf5"));
			assertEquals(2, syms.length);
			assertEquals("SampleLabel", syms[0].getName());
			assertEquals(SymbolType.FUNCTION, syms[0].getSymbolType());
			assertEquals("MY.DLL", syms[0].getParentNamespace().getName());
			assertEquals(SymbolType.NAMESPACE,
				syms[0].getParentNamespace().getSymbol().getSymbolType());
			assertEquals("MY.DLL_SampleLabel", syms[1].getName());
			assertEquals(SymbolType.LABEL, syms[1].getSymbolType());
			assertEquals("Global", syms[1].getParentNamespace().getName());
			assertEquals(SymbolType.GLOBAL,
				syms[1].getParentNamespace().getSymbol().getSymbolType());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testReplaceFunctionWhereLabel() throws Exception {
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
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						namespace = st.createNameSpace(program.getGlobalNamespace(), "MY.DLL",
							SourceType.USER_DEFINED);
						Function f = functionMgr.getFunctionAt(addr(program, "0x01002cf5"));
						f.setName("SampleLabel", SourceType.USER_DEFINED);
						f.setParentNamespace(namespace);
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

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x01001a00"), addr(p1, "0x01006500"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(
				ProgramDiffFilter.SYMBOL_DIFFS | ProgramDiffFilter.FUNCTION_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x01002cf5"), addr(p1, "0x01002cf5"));
			expectedDiffs.addRange(addr(p1, "0x010058f7"), addr(p1, "0x010058f7"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x01002cf5"), addr(p1, "0x01002cf5"));
			mergeSet.addRange(addr(p1, "0x010058f7"), addr(p1, "0x010058f7"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			assertEquals(new AddressSet(addr(p1, "0x010058f7"), addr(p1, "0x010058f7")),
				programMerge.getFilteredDifferences());

			SymbolTable st = p1.getSymbolTable();
			Symbol[] syms = st.getSymbols(addr(p1, "0x01002cf5"));
			assertEquals(1, syms.length);
			assertEquals("SampleLabel", syms[0].getName());
			assertEquals("MY.DLL", syms[0].getParentNamespace().getName());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testReplaceNamespaceLabelsButNotFunction() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					Namespace namespace = program.getGlobalNamespace();
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01002cf5"));
						f.setName("MY.DLL_SampleLabel", SourceType.USER_DEFINED);
						f.setParentNamespace(namespace);
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
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						namespace = st.createNameSpace(program.getGlobalNamespace(), "MY.DLL",
							SourceType.USER_DEFINED);
						Function f = functionMgr.getFunctionAt(addr(program, "0x01002cf5"));
						f.setName("SampleLabel", SourceType.USER_DEFINED);
						f.setParentNamespace(namespace);
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

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x01001a00"), addr(p1, "0x01006500"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(
				ProgramDiffFilter.SYMBOL_DIFFS | ProgramDiffFilter.FUNCTION_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.SYMBOLS, ProgramMergeFilter.REPLACE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x01002cf5"), addr(p1, "0x01002cf5"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x01002cf5"), addr(p1, "0x01002cf5"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			assertEquals(new AddressSet(), programMerge.getFilteredDifferences());

			SymbolTable st = p1.getSymbolTable();
			Symbol[] syms = st.getSymbols(addr(p1, "0x01002cf5"));
			assertEquals(1, syms.length);
			assertEquals("SampleLabel", syms[0].getName());
			assertEquals("MY.DLL", syms[0].getParentNamespace().getName());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testReplaceNamespaceLabelsAndFunction() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					Namespace namespace = program.getGlobalNamespace();
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01002cf5"));
						f.setName("MY.DLL_SampleLabel", SourceType.USER_DEFINED);
						f.setParentNamespace(namespace);
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
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						namespace = st.createNameSpace(program.getGlobalNamespace(), "MY.DLL",
							SourceType.USER_DEFINED);
						Function f = functionMgr.getFunctionAt(addr(program, "0x01002cf5"));
						f.setName("SampleLabel", SourceType.USER_DEFINED);
						f.setParentNamespace(namespace);
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

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x01001a00"), addr(p1, "0x01006500"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(
				ProgramDiffFilter.SYMBOL_DIFFS | ProgramDiffFilter.FUNCTION_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.SYMBOLS | ProgramMergeFilter.FUNCTIONS,
					ProgramMergeFilter.REPLACE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x01002cf5"), addr(p1, "0x01002cf5"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x01002cf5"), addr(p1, "0x01002cf5"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			assertEquals(new AddressSet(), programMerge.getFilteredDifferences());

			SymbolTable st = p1.getSymbolTable();
			Symbol[] syms = st.getSymbols(addr(p1, "0x01002cf5"));
			assertEquals(1, syms.length);
			assertEquals("SampleLabel", syms[0].getName());
			assertEquals("MY.DLL", syms[0].getParentNamespace().getName());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testMergeNamespaceLabelsButNotFunction() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					Namespace namespace = program.getGlobalNamespace();
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01002cf5"));
						f.setName("MY.DLL_SampleLabel", SourceType.USER_DEFINED);
						f.setParentNamespace(namespace);
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
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						namespace = st.createNameSpace(program.getGlobalNamespace(), "MY.DLL",
							SourceType.USER_DEFINED);
						Function f = functionMgr.getFunctionAt(addr(program, "0x01002cf5"));
						f.setName("SampleLabel", SourceType.USER_DEFINED);
						f.setParentNamespace(namespace);
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

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x01001a00"), addr(p1, "0x01006500"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(
				ProgramDiffFilter.SYMBOL_DIFFS | ProgramDiffFilter.FUNCTION_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.SYMBOLS, ProgramMergeFilter.MERGE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x01002cf5"), addr(p1, "0x01002cf5"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x01002cf5"), addr(p1, "0x01002cf5"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			SymbolTable st = p1.getSymbolTable();
			Symbol[] syms = st.getSymbols(addr(p1, "0x01002cf5"));
			assertEquals(2, syms.length);
			assertEquals("MY.DLL_SampleLabel", syms[0].getName());
			assertEquals("Global", syms[0].getParentNamespace().getName());
			assertEquals(true, syms[0].isPrimary());
			assertEquals(SymbolType.FUNCTION, syms[0].getSymbolType());
			assertEquals("SampleLabel", syms[1].getName());
			assertEquals("MY.DLL", syms[1].getParentNamespace().getName());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testMergeNamespaceLabelsAndFunction() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					Namespace namespace = program.getGlobalNamespace();
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01002cf5"));
						f.setName("MY.DLL_SampleLabel", SourceType.USER_DEFINED);
						f.setParentNamespace(namespace);
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
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						namespace = st.createNameSpace(program.getGlobalNamespace(), "MY.DLL",
							SourceType.USER_DEFINED);
						Function f = functionMgr.getFunctionAt(addr(program, "0x01002cf5"));
						f.setName("SampleLabel", SourceType.USER_DEFINED);
						f.setParentNamespace(namespace);
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

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x01001a00"), addr(p1, "0x01006500"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(
				ProgramDiffFilter.SYMBOL_DIFFS | ProgramDiffFilter.FUNCTION_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.SYMBOLS | ProgramMergeFilter.FUNCTIONS,
					ProgramMergeFilter.MERGE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x01002cf5"), addr(p1, "0x01002cf5"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x01002cf5"), addr(p1, "0x01002cf5"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			SymbolTable st = p1.getSymbolTable();
			Symbol[] syms = st.getSymbols(addr(p1, "0x01002cf5"));
			assertEquals(2, syms.length);
			assertEquals("SampleLabel", syms[0].getName());
			assertEquals("MY.DLL", syms[0].getParentNamespace().getName());
			assertEquals("MY.DLL_SampleLabel", syms[1].getName());
			assertEquals("Global", syms[1].getParentNamespace().getName());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testMergeNamespaceLabelsSetPrimaryButNotFunction() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					Namespace namespace = program.getGlobalNamespace();
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01002cf5"));
						f.setName("MY.DLL_SampleLabel", SourceType.USER_DEFINED);
						f.setParentNamespace(namespace);
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
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						namespace = st.createNameSpace(program.getGlobalNamespace(), "MY.DLL",
							SourceType.USER_DEFINED);
						Function f = functionMgr.getFunctionAt(addr(program, "0x01002cf5"));
						f.setName("SampleLabel", SourceType.USER_DEFINED);
						f.setParentNamespace(namespace);
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

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x01001a00"), addr(p1, "0x01006500"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(
				ProgramDiffFilter.SYMBOL_DIFFS | ProgramDiffFilter.FUNCTION_DIFFS));
			programMerge.setMergeFilter(new ProgramMergeFilter(
				ProgramMergeFilter.SYMBOLS | ProgramMergeFilter.PRIMARY_SYMBOL,
				ProgramMergeFilter.MERGE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x01002cf5"), addr(p1, "0x01002cf5"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x01002cf5"), addr(p1, "0x01002cf5"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			SymbolTable st = p1.getSymbolTable();
			Symbol[] syms = st.getSymbols(addr(p1, "0x01002cf5"));
			assertEquals(2, syms.length);
			assertEquals("SampleLabel", syms[0].getName());
			assertEquals("MY.DLL", syms[0].getParentNamespace().getName());
			assertEquals("MY.DLL_SampleLabel", syms[1].getName());
			assertEquals("Global", syms[1].getParentNamespace().getName());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testMergeNamespaceLabelsSetPrimaryAndFunction() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					Namespace namespace = program.getGlobalNamespace();
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01002cf5"));
						f.setName("MY.DLL_SampleLabel", SourceType.USER_DEFINED);
						f.setParentNamespace(namespace);
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
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						namespace = st.createNameSpace(program.getGlobalNamespace(), "MY.DLL",
							SourceType.USER_DEFINED);
						Function f = functionMgr.getFunctionAt(addr(program, "0x01002cf5"));
						f.setName("SampleLabel", SourceType.USER_DEFINED);
						f.setParentNamespace(namespace);
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

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x01001a00"), addr(p1, "0x01006500"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(
				ProgramDiffFilter.SYMBOL_DIFFS | ProgramDiffFilter.FUNCTION_DIFFS));
			programMerge.setMergeFilter(new ProgramMergeFilter(ProgramMergeFilter.SYMBOLS |
				ProgramMergeFilter.PRIMARY_SYMBOL | ProgramMergeFilter.FUNCTIONS,
				ProgramMergeFilter.MERGE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x01002cf5"), addr(p1, "0x01002cf5"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x01002cf5"), addr(p1, "0x01002cf5"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			SymbolTable st = p1.getSymbolTable();
			Symbol[] syms = st.getSymbols(addr(p1, "0x01002cf5"));
			assertEquals(2, syms.length);
			assertEquals("SampleLabel", syms[0].getName());
			assertEquals("MY.DLL", syms[0].getParentNamespace().getName());
			assertEquals("MY.DLL_SampleLabel", syms[1].getName());
			assertEquals("Global", syms[1].getParentNamespace().getName());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testReplaceSymbolSource() throws Exception {
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
						// 0100248f is default function
						program.getFunctionManager()
							.getFunctionAt(addr(program, "0x0100248f"))
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
						// 0100248f is default function
						program.getFunctionManager()
							.getFunctionAt(addr(program, "0x0100248f"))
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

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.SYMBOLS, ProgramMergeFilter.REPLACE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x01001ea0"), addr(p1, "0x01001ea0"));
			expectedDiffs.addRange(addr(p1, "0x01001ea9"), addr(p1, "0x01001ea9"));
			expectedDiffs.addRange(addr(p1, "0x01001eb5"), addr(p1, "0x01001eb5"));
			expectedDiffs.addRange(addr(p1, "0x01001ebc"), addr(p1, "0x01001ebc"));
			expectedDiffs.addRange(addr(p1, "0x0100248f"), addr(p1, "0x0100248f"));
			expectedDiffs.addRange(addr(p1, "0x1002691"), addr(p1, "0x1002691"));// Label in the 100248f namespace.
//			printAddressSet(expectedDiffs);
//			printAddressSet(programMerge.getFilteredDifferences());
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.add(expectedDiffs);
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			assertEquals(new AddressSet(), programMerge.getFilteredDifferences());

			SymbolTable st = p1.getSymbolTable();

			Symbol[] syms = st.getSymbols(addr(p1, "0x0100248f"));
			assertEquals(1, syms.length);
			assertEquals("Bud", syms[0].getName());
			assertEquals(SourceType.ANALYSIS, syms[0].getSource());

			syms = st.getSymbols(addr(p1, "0x01001ea0"));
			assertEquals(1, syms.length);
			assertEquals("Zero", syms[0].getName());
			assertEquals(SourceType.ANALYSIS, syms[0].getSource());

			syms = st.getSymbols(addr(p1, "0x01001ea9"));
			assertEquals(1, syms.length);
			assertEquals("One", syms[0].getName());
			assertEquals(SourceType.IMPORTED, syms[0].getSource());

			syms = st.getSymbols(addr(p1, "0x01001eb5"));
			assertEquals(1, syms.length);
			assertEquals("Two", syms[0].getName());
			assertEquals(SourceType.ANALYSIS, syms[0].getSource());

			syms = st.getSymbols(addr(p1, "0x01001ebc"));
			assertEquals(1, syms.length);
			assertEquals("Three", syms[0].getName());
			assertEquals(SourceType.USER_DEFINED, syms[0].getSource());

			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testMergeSymbolSource() throws Exception {
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
						// 0100248f is default function
						program.getFunctionManager()
							.getFunctionAt(addr(program, "0x0100248f"))
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
						// 0100248f is default function
						program.getFunctionManager()
							.getFunctionAt(addr(program, "0x0100248f"))
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

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.SYMBOLS, ProgramMergeFilter.MERGE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x01001ea0"), addr(p1, "0x01001ea0"));
			expectedDiffs.addRange(addr(p1, "0x01001ea9"), addr(p1, "0x01001ea9"));
			expectedDiffs.addRange(addr(p1, "0x01001eb5"), addr(p1, "0x01001eb5"));
			expectedDiffs.addRange(addr(p1, "0x01001ebc"), addr(p1, "0x01001ebc"));
			expectedDiffs.addRange(addr(p1, "0x0100248f"), addr(p1, "0x0100248f"));
			expectedDiffs.addRange(addr(p1, "0x1002691"), addr(p1, "0x1002691"));// Label in the 100248f namespace.
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.add(expectedDiffs);
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			assertEquals(mergeSet, programMerge.getFilteredDifferences());

			SymbolTable st = p1.getSymbolTable();

			Symbol[] syms = st.getSymbols(addr(p1, "0x0100248f"));
			assertEquals(1, syms.length);
			assertEquals("Bud", syms[0].getName());
			assertEquals(SourceType.IMPORTED, syms[0].getSource());

			syms = st.getSymbols(addr(p1, "0x01001ea0"));
			assertEquals(1, syms.length);
			assertEquals("Zero", syms[0].getName());
			assertEquals(SourceType.IMPORTED, syms[0].getSource());

			syms = st.getSymbols(addr(p1, "0x01001ea9"));
			assertEquals(1, syms.length);
			assertEquals("One", syms[0].getName());
			assertEquals(SourceType.USER_DEFINED, syms[0].getSource());

			syms = st.getSymbols(addr(p1, "0x01001eb5"));
			assertEquals(1, syms.length);
			assertEquals("Two", syms[0].getName());
			assertEquals(SourceType.IMPORTED, syms[0].getSource());

			syms = st.getSymbols(addr(p1, "0x01001ebc"));
			assertEquals(1, syms.length);
			assertEquals("Three", syms[0].getName());
			assertEquals(SourceType.ANALYSIS, syms[0].getSource());

			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testReplaceToAddVarArgs() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					Namespace namespace = program.getGlobalNamespace();
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01004132"));
						f.setName("printf", SourceType.USER_DEFINED);
						f.setParentNamespace(namespace);
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
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01004132"));
						// Already has a "undefined4 param_1".
						f.setVarArgs(true);
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
		Address entryPoint1 = addr(p1, "0x01004132");
		FunctionManager fm1 = p1.getFunctionManager();

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x01001a00"), addr(p1, "0x01006500"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(
				ProgramDiffFilter.SYMBOL_DIFFS | ProgramDiffFilter.FUNCTION_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x01004132"), addr(p1, "0x01004132"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x01004132"), addr(p1, "0x01004132"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			assertEquals(new AddressSet(), programMerge.getFilteredDifferences());

			Function f = fm1.getFunctionAt(entryPoint1);
			assertEquals("FUN_01004132", f.getName());
			assertEquals(true, f.hasVarArgs());
			assertEquals(1, f.getParameterCount());
			Parameter[] parameters = f.getParameters();
			assertTrue(parameters[0].getDataType().isEquivalent(new Undefined4DataType()));
			assertEquals("param_1", parameters[0].getName());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testReplaceToRemoveVarArgs() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01004132"));
						f.setVarArgs(true);
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
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01004132"));
						// Already has a "undefined4 param_1".
						Variable var = new LocalVariableImpl(null, new DWordDataType(), 8, program);
						f.addParameter(var, SourceType.USER_DEFINED);
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
		Address entryPoint1 = addr(p1, "0x01004132");
		FunctionManager fm1 = p1.getFunctionManager();

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x01001a00"), addr(p1, "0x01006500"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(
				ProgramDiffFilter.SYMBOL_DIFFS | ProgramDiffFilter.FUNCTION_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x01004132"), addr(p1, "0x01004132"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x01004132"), addr(p1, "0x01004132"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			assertEquals(new AddressSet(), programMerge.getFilteredDifferences());

			Function f = fm1.getFunctionAt(entryPoint1);
			assertEquals("FUN_01004132", f.getName());
			assertEquals(false, f.hasVarArgs());
			assertEquals(2, f.getParameterCount());
			Parameter[] parameters = f.getParameters();
			assertTrue(parameters[0].getDataType().isEquivalent(new Undefined4DataType()));
			assertEquals("param_1", parameters[0].getName());
			assertTrue(parameters[1].getDataType().isEquivalent(new DWordDataType()));
			assertEquals("param_2", parameters[1].getName());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testReplaceToSetInline() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					Namespace namespace = program.getGlobalNamespace();
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01004132"));
						f.setName("printf", SourceType.USER_DEFINED);
						f.setParentNamespace(namespace);
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
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01004132"));
						// Already has a "undefined4 param_1".
						f.setInline(true);
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
		Address entryPoint1 = addr(p1, "0x01004132");
		FunctionManager fm1 = p1.getFunctionManager();

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x01001a00"), addr(p1, "0x01006500"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(
				ProgramDiffFilter.SYMBOL_DIFFS | ProgramDiffFilter.FUNCTION_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x01004132"), addr(p1, "0x01004132"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x01004132"), addr(p1, "0x01004132"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			assertEquals(new AddressSet(), programMerge.getFilteredDifferences());

			Function f = fm1.getFunctionAt(entryPoint1);
			assertEquals("FUN_01004132", f.getName());
			assertEquals(true, f.isInline());
			assertEquals(1, f.getParameterCount());
			Parameter[] parameters = f.getParameters();
			assertTrue(parameters[0].getDataType().isEquivalent(new Undefined4DataType()));
			assertEquals("param_1", parameters[0].getName());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testReplaceToUnsetInline() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01004132"));
						f.setInline(true);
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
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01004132"));
						// Already has a "undefined4 param_1".
						Variable var = new LocalVariableImpl(null, new DWordDataType(), 8, program);
						f.addParameter(var, SourceType.USER_DEFINED);
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
		Address entryPoint1 = addr(p1, "0x01004132");
		FunctionManager fm1 = p1.getFunctionManager();

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x01004132"), addr(p1, "0x01004132"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(
				ProgramDiffFilter.SYMBOL_DIFFS | ProgramDiffFilter.FUNCTION_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x01004132"), addr(p1, "0x01004132"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x01004132"), addr(p1, "0x01004132"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			assertEquals(new AddressSet(), programMerge.getFilteredDifferences());

			Function f = fm1.getFunctionAt(entryPoint1);
			assertEquals("FUN_01004132", f.getName());
			assertEquals(false, f.isInline());
			assertEquals(2, f.getParameterCount());
			Parameter[] parameters = f.getParameters();
			assertTrue(parameters[0].getDataType().isEquivalent(new Undefined4DataType()));
			assertEquals("param_1", parameters[0].getName());
			assertTrue(parameters[1].getDataType().isEquivalent(new DWordDataType()));
			assertEquals("param_2", parameters[1].getName());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testReplaceToSetNoReturn() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					Namespace namespace = program.getGlobalNamespace();
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01004132"));
						f.setName("printf", SourceType.USER_DEFINED);
						f.setParentNamespace(namespace);
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
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01004132"));
						// Already has a "undefined4 param_1".
						f.setNoReturn(true);
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
		Address entryPoint1 = addr(p1, "0x01004132");
		FunctionManager fm1 = p1.getFunctionManager();

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x01004132"), addr(p1, "0x01004132"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(
				ProgramDiffFilter.SYMBOL_DIFFS | ProgramDiffFilter.FUNCTION_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x01004132"), addr(p1, "0x01004132"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x01004132"), addr(p1, "0x01004132"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			assertEquals(new AddressSet(), programMerge.getFilteredDifferences());

			Function f = fm1.getFunctionAt(entryPoint1);
			assertEquals("FUN_01004132", f.getName());
			assertEquals(true, f.hasNoReturn());
			assertEquals(1, f.getParameterCount());
			Parameter[] parameters = f.getParameters();
			assertTrue(parameters[0].getDataType().isEquivalent(new Undefined4DataType()));
			assertEquals("param_1", parameters[0].getName());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testReplaceToUnsetNoReturn() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01004132"));
						f.setNoReturn(true);
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
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01004132"));
						// Already has a "undefined4 param_1".
						Variable var = new LocalVariableImpl(null, new DWordDataType(), 8, program);
						f.addParameter(var, SourceType.USER_DEFINED);
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
		Address entryPoint1 = addr(p1, "0x01004132");
		FunctionManager fm1 = p1.getFunctionManager();

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x01001a00"), addr(p1, "0x01006500"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(
				ProgramDiffFilter.SYMBOL_DIFFS | ProgramDiffFilter.FUNCTION_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x01004132"), addr(p1, "0x01004132"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x01004132"), addr(p1, "0x01004132"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			assertEquals(new AddressSet(), programMerge.getFilteredDifferences());

			Function f = fm1.getFunctionAt(entryPoint1);
			assertEquals("FUN_01004132", f.getName());
			assertEquals(false, f.hasNoReturn());
			assertEquals(2, f.getParameterCount());
			Parameter[] parameters = f.getParameters();
			assertTrue(parameters[0].getDataType().isEquivalent(new Undefined4DataType()));
			assertEquals("param_1", parameters[0].getName());
			assertTrue(parameters[1].getDataType().isEquivalent(new DWordDataType()));
			assertEquals("param_2", parameters[1].getName());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testMergeFunctionTags() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01004132"));
						f.addTag("TagA");
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
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01004132"));
						f.addTag("TagB");
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
		Address entryPoint1 = addr(p1, "0x01004132");
		FunctionManager fm1 = p1.getFunctionManager();

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x01001a00"), addr(p1, "0x01006500"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(
				ProgramDiffFilter.FUNCTION_TAG_DIFFS | ProgramDiffFilter.FUNCTION_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.FUNCTION_TAGS, ProgramMergeFilter.MERGE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x01004132"), addr(p1, "0x01004132"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x01004132"), addr(p1, "0x01004132"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			Function f = fm1.getFunctionAt(entryPoint1);
			assertEquals("FUN_01004132", f.getName());
			Set<FunctionTag> tags = f.getTags();
			List<String> tagNames = new ArrayList<>();
			for (FunctionTag tag : tags) {
				tagNames.add(tag.getName());
			}

			assertTrue(tagNames.size() == 2);
			assertTrue(tagNames.contains("TagA"));
			assertTrue(tagNames.contains("TagB"));

			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testReplaceFunctionTags() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01004132"));
						f.addTag("TagA");
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
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01004132"));
						f.addTag("TagB");
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
		Address entryPoint1 = addr(p1, "0x01004132");
		FunctionManager fm1 = p1.getFunctionManager();

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x01001a00"), addr(p1, "0x01006500"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(
				ProgramDiffFilter.FUNCTION_TAG_DIFFS | ProgramDiffFilter.FUNCTION_DIFFS));
			programMerge.setMergeFilter(new ProgramMergeFilter(ProgramMergeFilter.FUNCTION_TAGS,
				ProgramMergeFilter.REPLACE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x01004132"), addr(p1, "0x01004132"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x01004132"), addr(p1, "0x01004132"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			Function f = fm1.getFunctionAt(entryPoint1);
			assertEquals("FUN_01004132", f.getName());
			Set<FunctionTag> tags = f.getTags();
			List<String> tagNames = new ArrayList<>();
			for (FunctionTag tag : tags) {
				tagNames.add(tag.getName());
			}

			assertTrue(tagNames.size() == 1);
			assertTrue(tagNames.contains("TagB"));

			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	// Replace unknown calling convention with each of other types.
	@Test
	public void testReplaceCallingConvention1() throws Exception {
		// NotepadMergeListingTest_X86 has "unknown", "default", "__stdcall", "__cdecl", "__fastcall", "__thiscall".
		// 01006420 entry()
		// 01001ae3 FUN_01001ae3(p1,p2)
		// 010021f3 FUN_010021f3(p1)
		// 0100248f FUN_0100248f(p1,p2,p3,p4)
		// 01002c93 FUN_01002c93(p1,p2,p3)

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// P2 program
				int txId = program.startTransaction("Modify Program 2");
				boolean commit = false;
				try {
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01006420"));
						f.setCallingConvention(Function.DEFAULT_CALLING_CONVENTION_STRING);
						f = functionMgr.getFunctionAt(addr(program, "0x01001ae3"));
						f.setCallingConvention("__stdcall");
						f = functionMgr.getFunctionAt(addr(program, "0x010021f3"));
						f.setCallingConvention("__thiscall");
						f = functionMgr.getFunctionAt(addr(program, "0x0100248f"));
						f.setCallingConvention("__fastcall");
						f = functionMgr.getFunctionAt(addr(program, "0x01002c93"));
						f.setCallingConvention("__cdecl");
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
		Address entryPoint1 = addr(p1, "0x01006420");
		Address entryPoint2 = addr(p1, "0x01001ae3");
		Address entryPoint3 = addr(p1, "0x010021f3");
		Address entryPoint4 = addr(p1, "0x0100248f");
		Address entryPoint5 = addr(p1, "0x01002c93");
		FunctionManager fm1 = p1.getFunctionManager();

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x01001a00"), addr(p1, "0x01006500"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(
				ProgramDiffFilter.SYMBOL_DIFFS | ProgramDiffFilter.FUNCTION_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(entryPoint1, entryPoint1);
			expectedDiffs.addRange(entryPoint2, entryPoint2);
			expectedDiffs.addRange(entryPoint3, entryPoint3);
			expectedDiffs.addRange(entryPoint4, entryPoint4);
			expectedDiffs.addRange(entryPoint5, entryPoint5);
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			Function f = fm1.getFunctionAt(entryPoint1);
			assertEquals("entry", f.getName());
			assertEquals(Function.UNKNOWN_CALLING_CONVENTION_STRING, f.getCallingConventionName());
			f = fm1.getFunctionAt(entryPoint2);
			assertEquals(Function.UNKNOWN_CALLING_CONVENTION_STRING, f.getCallingConventionName());
			f = fm1.getFunctionAt(entryPoint3);
			assertEquals(Function.UNKNOWN_CALLING_CONVENTION_STRING, f.getCallingConventionName());
			f = fm1.getFunctionAt(entryPoint4);
			assertEquals(Function.UNKNOWN_CALLING_CONVENTION_STRING, f.getCallingConventionName());
			f = fm1.getFunctionAt(entryPoint5);
			assertEquals(Function.UNKNOWN_CALLING_CONVENTION_STRING, f.getCallingConventionName());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x01001a00"), addr(p1, "0x01006500"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			assertEquals(new AddressSet(), programMerge.getFilteredDifferences());

			f = fm1.getFunctionAt(entryPoint1);
			assertEquals("entry", f.getName());
			assertEquals(Function.DEFAULT_CALLING_CONVENTION_STRING, f.getCallingConventionName());
			f = fm1.getFunctionAt(entryPoint2);
			assertEquals("FUN_01001ae3", f.getName());
			assertEquals("__stdcall", f.getCallingConventionName());
			f = fm1.getFunctionAt(entryPoint3);
			assertEquals("FUN_010021f3", f.getName());
			assertEquals("__thiscall", f.getCallingConventionName());
			f = fm1.getFunctionAt(entryPoint4);
			assertEquals("FUN_0100248f", f.getName());
			assertEquals("__fastcall", f.getCallingConventionName());
			f = fm1.getFunctionAt(entryPoint5);
			assertEquals("FUN_01002c93", f.getName());
			assertEquals("__cdecl", f.getCallingConventionName());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	// Replace default calling convention with each of other types.
	@Test
	public void testReplaceCallingConvention2() throws Exception {
		// NotepadMergeListingTest_X86 has "unknown", "default", "__stdcall", "__cdecl", "__fastcall", "__thiscall".
		// 01006420 entry()
		// 01001ae3 FUN_01001ae3(p1,p2)
		// 010021f3 FUN_010021f3(p1)
		// 0100248f FUN_0100248f(p1,p2,p3,p4)
		// 01002c93 FUN_01002c93(p1,p2,p3)

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01006420"));
						f.setCallingConvention(Function.DEFAULT_CALLING_CONVENTION_STRING);
						f = functionMgr.getFunctionAt(addr(program, "0x01001ae3"));
						f.setCallingConvention(Function.DEFAULT_CALLING_CONVENTION_STRING);
						f = functionMgr.getFunctionAt(addr(program, "0x010021f3"));
						f.setCallingConvention(Function.DEFAULT_CALLING_CONVENTION_STRING);
						f = functionMgr.getFunctionAt(addr(program, "0x0100248f"));
						f.setCallingConvention(Function.DEFAULT_CALLING_CONVENTION_STRING);
						f = functionMgr.getFunctionAt(addr(program, "0x01002c93"));
						f.setCallingConvention(Function.DEFAULT_CALLING_CONVENTION_STRING);
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
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01006420"));
						f.setCallingConvention(Function.UNKNOWN_CALLING_CONVENTION_STRING);
						f = functionMgr.getFunctionAt(addr(program, "0x01001ae3"));
						f.setCallingConvention("__stdcall");
						f = functionMgr.getFunctionAt(addr(program, "0x010021f3"));
						f.setCallingConvention("__thiscall");
						f = functionMgr.getFunctionAt(addr(program, "0x0100248f"));
						f.setCallingConvention("__fastcall");
						f = functionMgr.getFunctionAt(addr(program, "0x01002c93"));
						f.setCallingConvention("__cdecl");
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
		Address entryPoint1 = addr(p1, "0x01006420");
		Address entryPoint2 = addr(p1, "0x01001ae3");
		Address entryPoint3 = addr(p1, "0x010021f3");
		Address entryPoint4 = addr(p1, "0x0100248f");
		Address entryPoint5 = addr(p1, "0x01002c93");
		FunctionManager fm1 = p1.getFunctionManager();

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x01001a00"), addr(p1, "0x01006500"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(
				ProgramDiffFilter.SYMBOL_DIFFS | ProgramDiffFilter.FUNCTION_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(entryPoint1, entryPoint1);
			expectedDiffs.addRange(entryPoint2, entryPoint2);
			expectedDiffs.addRange(entryPoint3, entryPoint3);
			expectedDiffs.addRange(entryPoint4, entryPoint4);
			expectedDiffs.addRange(entryPoint5, entryPoint5);
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			Function f = fm1.getFunctionAt(entryPoint1);
			assertEquals("entry", f.getName());
			assertEquals(Function.DEFAULT_CALLING_CONVENTION_STRING, f.getCallingConventionName());
			f = fm1.getFunctionAt(entryPoint2);
			assertEquals(Function.DEFAULT_CALLING_CONVENTION_STRING, f.getCallingConventionName());
			f = fm1.getFunctionAt(entryPoint3);
			assertEquals(Function.DEFAULT_CALLING_CONVENTION_STRING, f.getCallingConventionName());
			f = fm1.getFunctionAt(entryPoint4);
			assertEquals(Function.DEFAULT_CALLING_CONVENTION_STRING, f.getCallingConventionName());
			f = fm1.getFunctionAt(entryPoint5);
			assertEquals(Function.DEFAULT_CALLING_CONVENTION_STRING, f.getCallingConventionName());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x01001a00"), addr(p1, "0x01006500"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			assertEquals(new AddressSet(), programMerge.getFilteredDifferences());

			f = fm1.getFunctionAt(entryPoint1);
			assertEquals("entry", f.getName());
			assertEquals(Function.UNKNOWN_CALLING_CONVENTION_STRING, f.getCallingConventionName());
			f = fm1.getFunctionAt(entryPoint2);
			assertEquals("FUN_01001ae3", f.getName());
			assertEquals("__stdcall", f.getCallingConventionName());
			f = fm1.getFunctionAt(entryPoint3);
			assertEquals("FUN_010021f3", f.getName());
			assertEquals("__thiscall", f.getCallingConventionName());
			f = fm1.getFunctionAt(entryPoint4);
			assertEquals("FUN_0100248f", f.getName());
			assertEquals("__fastcall", f.getCallingConventionName());
			f = fm1.getFunctionAt(entryPoint5);
			assertEquals("FUN_01002c93", f.getName());
			assertEquals("__cdecl", f.getCallingConventionName());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	// Replace stdcall calling convention with each of other types.
	@Test
	public void testReplaceCallingConvention3() throws Exception {
		// NotepadMergeListingTest_X86 has "unknown", "default", "__stdcall", "__cdecl", "__fastcall", "__thiscall".
		// 01006420 entry()
		// 01001ae3 FUN_01001ae3(p1,p2)
		// 010021f3 FUN_010021f3(p1)
		// 0100248f FUN_0100248f(p1,p2,p3,p4)
		// 01002c93 FUN_01002c93(p1,p2,p3)

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01006420"));
						f.setCallingConvention("__stdcall");
						f = functionMgr.getFunctionAt(addr(program, "0x01001ae3"));
						f.setCallingConvention("__stdcall");
						f = functionMgr.getFunctionAt(addr(program, "0x010021f3"));
						f.setCallingConvention("__stdcall");
						f = functionMgr.getFunctionAt(addr(program, "0x0100248f"));
						f.setCallingConvention("__stdcall");
						f = functionMgr.getFunctionAt(addr(program, "0x01002c93"));
						f.setCallingConvention("__stdcall");
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
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01006420"));
						f.setCallingConvention(Function.UNKNOWN_CALLING_CONVENTION_STRING);
						f = functionMgr.getFunctionAt(addr(program, "0x01001ae3"));
						f.setCallingConvention(Function.DEFAULT_CALLING_CONVENTION_STRING);
						f = functionMgr.getFunctionAt(addr(program, "0x010021f3"));
						f.setCallingConvention("__thiscall");
						f = functionMgr.getFunctionAt(addr(program, "0x0100248f"));
						f.setCallingConvention("__fastcall");
						f = functionMgr.getFunctionAt(addr(program, "0x01002c93"));
						f.setCallingConvention("__cdecl");
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
		Address entryPoint1 = addr(p1, "0x01006420");
		Address entryPoint2 = addr(p1, "0x01001ae3");
		Address entryPoint3 = addr(p1, "0x010021f3");
		Address entryPoint4 = addr(p1, "0x0100248f");
		Address entryPoint5 = addr(p1, "0x01002c93");
		FunctionManager fm1 = p1.getFunctionManager();

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x01001a00"), addr(p1, "0x01006500"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(
				ProgramDiffFilter.SYMBOL_DIFFS | ProgramDiffFilter.FUNCTION_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(entryPoint1, entryPoint1);
			expectedDiffs.addRange(entryPoint2, entryPoint2);
			expectedDiffs.addRange(entryPoint3, entryPoint3);
			expectedDiffs.addRange(entryPoint4, entryPoint4);
			expectedDiffs.addRange(entryPoint5, entryPoint5);
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			Function f = fm1.getFunctionAt(entryPoint1);
			assertEquals("entry", f.getName());
			assertEquals("__stdcall", f.getCallingConventionName());
			f = fm1.getFunctionAt(entryPoint2);
			assertEquals("__stdcall", f.getCallingConventionName());
			f = fm1.getFunctionAt(entryPoint3);
			assertEquals("__stdcall", f.getCallingConventionName());
			f = fm1.getFunctionAt(entryPoint4);
			assertEquals("__stdcall", f.getCallingConventionName());
			f = fm1.getFunctionAt(entryPoint5);
			assertEquals("__stdcall", f.getCallingConventionName());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x01001a00"), addr(p1, "0x01006500"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			assertEquals(new AddressSet(), programMerge.getFilteredDifferences());

			f = fm1.getFunctionAt(entryPoint1);
			assertEquals("entry", f.getName());
			assertEquals(Function.UNKNOWN_CALLING_CONVENTION_STRING, f.getCallingConventionName());
			f = fm1.getFunctionAt(entryPoint2);
			assertEquals("FUN_01001ae3", f.getName());
			assertEquals(Function.DEFAULT_CALLING_CONVENTION_STRING, f.getCallingConventionName());
			f = fm1.getFunctionAt(entryPoint3);
			assertEquals("FUN_010021f3", f.getName());
			assertEquals("__thiscall", f.getCallingConventionName());
			f = fm1.getFunctionAt(entryPoint4);
			assertEquals("FUN_0100248f", f.getName());
			assertEquals("__fastcall", f.getCallingConventionName());
			f = fm1.getFunctionAt(entryPoint5);
			assertEquals("FUN_01002c93", f.getName());
			assertEquals("__cdecl", f.getCallingConventionName());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testMergeOverlaySymbolsNoConflict() throws Exception {
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
		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			Address addr1630 = addr(p1, "TextOverlay::01001630");
			Address addr1639 = addr(p1, "TextOverlay::01001639");
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "TextOverlay::01001630"),
				addr(p1, "TextOverlay::0100182f"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.SYMBOLS, ProgramMergeFilter.MERGE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr1630, addr1630);
			expectedDiffs.addRange(addr1639, addr1639);
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "TextOverlay::01001630"), addr(p1, "TextOverlay::0100182f"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			assertEquals(new AddressSet(addr1630, addr1630), programMerge.getFilteredDifferences());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}

		SymbolTable resultSymTab = p1.getSymbolTable();
		Symbol[] symbols = resultSymTab.getSymbols(addr(p1, "TextOverlay::01001630"));
		assertEquals(1, symbols.length);
		assertEquals("OVL1630", symbols[0].getName());
		symbols = resultSymTab.getSymbols(addr(p1, "TextOverlay::01001639"));
		assertEquals(1, symbols.length);
		assertEquals("OVL1639", symbols[0].getName());
		symbols = resultSymTab.getSymbols(addr(p1, "TextOverlay::01001646"));
		assertEquals(1, symbols.length);
		assertEquals("OVL1646", symbols[0].getName());
	}

	@Test
	public void testReplaceConflictingOverlaySymbols() throws Exception {
		mtf.initialize("overlayCalc", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					SymbolTable st = program.getSymbolTable();
					try {
						st.createLabel(addr(program, "TextOverlay::01001630"), "OVL1630Latest",
							SourceType.USER_DEFINED);
						st.createLabel(addr(program, "TextOverlay::01001639"), "OVL1639Latest",
							SourceType.USER_DEFINED);
						st.createLabel(addr(program, "TextOverlay::01001646"), "OVL1646Latest",
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
						st.createLabel(addr(program, "TextOverlay::01001630"), "OVL1630My",
							SourceType.USER_DEFINED);
						st.createLabel(addr(program, "TextOverlay::01001639"), "OVL1639My",
							SourceType.USER_DEFINED);
						st.createLabel(addr(program, "TextOverlay::01001646"), "OVL1646My",
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
		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			Address addr1630 = addr(p1, "TextOverlay::01001630");
			Address addr1639 = addr(p1, "TextOverlay::01001639");
			Address addr1646 = addr(p1, "TextOverlay::01001646");
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "TextOverlay::01001630"),
				addr(p1, "TextOverlay::0100182f"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.SYMBOLS, ProgramMergeFilter.REPLACE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr1630, addr1630);
			expectedDiffs.addRange(addr1639, addr1639);
			expectedDiffs.addRange(addr1646, addr1646);
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "TextOverlay::01001630"), addr(p1, "TextOverlay::01001630"));
			mergeSet.addRange(addr(p1, "TextOverlay::01001646"), addr(p1, "TextOverlay::01001646"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}

		SymbolTable resultSymTab = p1.getSymbolTable();
		Symbol[] symbols = resultSymTab.getSymbols(addr(p1, "TextOverlay::01001630"));
		assertEquals(1, symbols.length);
		assertEquals("OVL1630My", symbols[0].getName());
		symbols = resultSymTab.getSymbols(addr(p1, "TextOverlay::01001639"));
		assertEquals(1, symbols.length);
		assertEquals("OVL1639Latest", symbols[0].getName());
		symbols = resultSymTab.getSymbols(addr(p1, "TextOverlay::01001646"));
		assertEquals(1, symbols.length);
		assertEquals("OVL1646My", symbols[0].getName());
	}

	@Test
	public void testMergeConflictingOverlaySymbols() throws Exception {
		mtf.initialize("overlayCalc", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					SymbolTable st = program.getSymbolTable();
					try {
						st.createLabel(addr(program, "TextOverlay::01001630"), "OVL1630Latest",
							SourceType.USER_DEFINED);
						st.createLabel(addr(program, "TextOverlay::01001639"), "OVL1639Latest",
							SourceType.USER_DEFINED);
						st.createLabel(addr(program, "TextOverlay::01001646"), "OVL1646Latest",
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
						st.createLabel(addr(program, "TextOverlay::01001630"), "OVL1630My",
							SourceType.USER_DEFINED);
						st.createLabel(addr(program, "TextOverlay::01001639"), "OVL1639My",
							SourceType.USER_DEFINED);
						st.createLabel(addr(program, "TextOverlay::01001646"), "OVL1646My",
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
		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			Address addr1630 = addr(p1, "TextOverlay::01001630");
			Address addr1639 = addr(p1, "TextOverlay::01001639");
			Address addr1646 = addr(p1, "TextOverlay::01001646");
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "TextOverlay::01001630"),
				addr(p1, "TextOverlay::0100182f"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.SYMBOLS, ProgramMergeFilter.MERGE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr1630, addr1630);
			expectedDiffs.addRange(addr1639, addr1639);
			expectedDiffs.addRange(addr1646, addr1646);
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "TextOverlay::01001630"), addr(p1, "TextOverlay::0100182f"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}

		SymbolTable resultSymTab = p1.getSymbolTable();
		Symbol[] symbols = resultSymTab.getSymbols(addr(p1, "TextOverlay::01001630"));
		assertEquals(2, symbols.length);
		assertEquals("OVL1630Latest", symbols[0].getName());
		assertEquals("OVL1630My", symbols[1].getName());
		symbols = resultSymTab.getSymbols(addr(p1, "TextOverlay::01001639"));
		assertEquals(2, symbols.length);
		assertEquals("OVL1639Latest", symbols[0].getName());
		assertEquals("OVL1639My", symbols[1].getName());
		symbols = resultSymTab.getSymbols(addr(p1, "TextOverlay::01001646"));
		assertEquals(2, symbols.length);
		assertEquals("OVL1646Latest", symbols[0].getName());
		assertEquals("OVL1646My", symbols[1].getName());
	}

	@Test
	public void testMergeOfOverlapOverlaysWithChanges() throws Exception {
		// FIXME This isn't actually merging. Also the overlays are considered different and don't currently overlap.
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

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			programMerge = new ProgramMergeManager(p1, p2, null, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(
				ProgramDiffFilter.SYMBOL_DIFFS | ProgramDiffFilter.FUNCTION_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
			// Only program1's symbol Diffs are found since program2's overlay is not compatible with program1.
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "Foo:0x01000030"), addr(p1, "Foo:0x01000030"));
			expectedDiffs.addRange(addr(p1, "Foo:0x01000079"), addr(p1, "Foo:0x01000079"));
			expectedDiffs.addRange(addr(p1, "Foo:0x0100017f"), addr(p1, "Foo:0x0100017f"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testReplaceOverlayLabels() throws Exception {
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
						st.createLabel(addr(program, "Foo::0x01000030"), "Sample0030",
							globalNamespace, SourceType.USER_DEFINED);
						st.createLabel(addr(program, "Foo::0x0100007f"), "Sample007f",
							globalNamespace, SourceType.USER_DEFINED);
						st.createLabel(addr(program, "Foo::0x0100017f"), "Sample017f",
							globalNamespace, SourceType.USER_DEFINED);
						st.createLabel(addr(program, "Foo::0x01000100"), "Sample0100",
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
						st.createLabel(addr(program, "Foo::0x01000080"), "Other0080",
							globalNamespace, SourceType.USER_DEFINED);
						st.createLabel(addr(program, "Foo::0x01000180"), "Other0180",
							globalNamespace, SourceType.USER_DEFINED);
						st.createLabel(addr(program, "Foo::0x010001ff"), "Other01ff",
							globalNamespace, SourceType.USER_DEFINED);
						st.createLabel(addr(program, "Foo::0x01000100"), "Other0100",
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

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			programMerge = new ProgramMergeManager(p1, p2, null, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(
				ProgramDiffFilter.SYMBOL_DIFFS | ProgramDiffFilter.FUNCTION_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.SYMBOLS, ProgramMergeFilter.REPLACE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "Foo::0x01000030"), addr(p1, "Foo::0x01000030"));
			expectedDiffs.addRange(addr(p1, "Foo::0x0100007f"), addr(p1, "Foo::0x0100007f"));
			expectedDiffs.addRange(addr(p1, "Foo::0x01000080"), addr(p1, "Foo::0x01000080"));
			expectedDiffs.addRange(addr(p1, "Foo::0x01000100"), addr(p1, "Foo::0x01000100"));
			expectedDiffs.addRange(addr(p1, "Foo::0x0100017f"), addr(p1, "Foo::0x0100017f"));
			expectedDiffs.addRange(addr(p1, "Foo::0x01000180"), addr(p1, "Foo::0x01000180"));
			expectedDiffs.addRange(addr(p1, "Foo::0x010001ff"), addr(p1, "Foo::0x010001ff"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "Foo::0x01000030"), addr(p1, "Foo::0x01000030"));
			mergeSet.addRange(addr(p1, "Foo::0x0100007f"), addr(p1, "Foo::0x0100007f"));
			mergeSet.addRange(addr(p1, "Foo::0x01000080"), addr(p1, "Foo::0x01000080"));
			mergeSet.addRange(addr(p1, "Foo::0x01000100"), addr(p1, "Foo::0x01000100"));
			mergeSet.addRange(addr(p1, "Foo::0x0100017f"), addr(p1, "Foo::0x0100017f"));
			mergeSet.addRange(addr(p1, "Foo::0x01000180"), addr(p1, "Foo::0x01000180"));
			mergeSet.addRange(addr(p1, "Foo::0x010001ff"), addr(p1, "Foo::0x010001ff"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			assertEquals(new AddressSet(), programMerge.getFilteredDifferences());

			SymbolTable st = p1.getSymbolTable();
			Symbol[] symbols;
			symbols = st.getSymbols(addr(p1, "Foo::0x01000080"));
			assertEquals(1, symbols.length);
			assertEquals("Other0080", symbols[0].getName(true));

			symbols = st.getSymbols(addr(p1, "Foo::0x01000180"));
			assertEquals(1, symbols.length);
			assertEquals("Other0180", symbols[0].getName(true));

			symbols = st.getSymbols(addr(p1, "Foo::0x010001ff"));
			assertEquals(1, symbols.length);
			assertEquals("Other01ff", symbols[0].getName(true));

			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}

		ProgramDiff latestProgramDiff = new ProgramDiff(p1, mtf.getLatestProgram());
		AddressSet latestAddrSet = new AddressSet();
		latestAddrSet.addRange(addr(p1, "Foo::0x01000080"), addr(p1, "Foo::0x01000080"));
		latestAddrSet.addRange(addr(p1, "Foo::0x01000180"), addr(p1, "Foo::0x01000180"));
		latestAddrSet.addRange(addr(p1, "Foo::0x010001ff"), addr(p1, "Foo::0x010001ff"));
		latestAddrSet.addRange(addr(p1, "Foo::0x01000030"), addr(p1, "Foo::0x01000030"));
		latestAddrSet.addRange(addr(p1, "Foo::0x0100007f"), addr(p1, "Foo::0x0100007f"));
		latestAddrSet.addRange(addr(p1, "Foo::0x0100017f"), addr(p1, "Foo::0x0100017f"));
		latestAddrSet.addRange(addr(p1, "Foo::0x01000100"), addr(p1, "Foo::0x01000100"));
		latestProgramDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.ALL_DIFFS));
		assertEquals(latestAddrSet,
			latestProgramDiff.getDifferences(latestProgramDiff.getFilter(), null));

		ProgramDiff myProgramDiff = new ProgramDiff(p1, mtf.getPrivateProgram());
		AddressSet myAddrSet = new AddressSet();
		myProgramDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.ALL_DIFFS));
		assertEquals(myAddrSet, myProgramDiff.getDifferences(myProgramDiff.getFilter(), null));
	}

	@Test
	public void testMergeOverlayLabels() throws Exception {
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
						st.createLabel(addr(program, "Foo::0x01000030"), "Sample0030",
							globalNamespace, SourceType.USER_DEFINED);
						st.createLabel(addr(program, "Foo::0x0100007f"), "Sample007f",
							globalNamespace, SourceType.USER_DEFINED);
						st.createLabel(addr(program, "Foo::0x0100017f"), "Sample017f",
							globalNamespace, SourceType.USER_DEFINED);
						st.createLabel(addr(program, "Foo::0x01000100"), "Sample0100",
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
						st.createLabel(addr(program, "Foo::0x01000080"), "Other0080",
							globalNamespace, SourceType.USER_DEFINED);
						st.createLabel(addr(program, "Foo::0x01000180"), "Other0180",
							globalNamespace, SourceType.USER_DEFINED);
						st.createLabel(addr(program, "Foo::0x010001ff"), "Other01ff",
							globalNamespace, SourceType.USER_DEFINED);
						st.createLabel(addr(program, "Foo::0x01000100"), "Other0100",
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

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			programMerge = new ProgramMergeManager(p1, p2, null, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(
				ProgramDiffFilter.SYMBOL_DIFFS | ProgramDiffFilter.FUNCTION_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.SYMBOLS, ProgramMergeFilter.MERGE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "Foo::0x01000030"), addr(p1, "Foo::0x01000030"));
			expectedDiffs.addRange(addr(p1, "Foo::0x0100007f"), addr(p1, "Foo::0x0100007f"));
			expectedDiffs.addRange(addr(p1, "Foo::0x01000080"), addr(p1, "Foo::0x01000080"));
			expectedDiffs.addRange(addr(p1, "Foo::0x01000100"), addr(p1, "Foo::0x01000100"));
			expectedDiffs.addRange(addr(p1, "Foo::0x0100017f"), addr(p1, "Foo::0x0100017f"));
			expectedDiffs.addRange(addr(p1, "Foo::0x01000180"), addr(p1, "Foo::0x01000180"));
			expectedDiffs.addRange(addr(p1, "Foo::0x010001ff"), addr(p1, "Foo::0x010001ff"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "Foo::0x01000030"), addr(p1, "Foo::0x01000030"));
			mergeSet.addRange(addr(p1, "Foo::0x0100007f"), addr(p1, "Foo::0x0100007f"));
			mergeSet.addRange(addr(p1, "Foo::0x01000080"), addr(p1, "Foo::0x01000080"));
			mergeSet.addRange(addr(p1, "Foo::0x01000100"), addr(p1, "Foo::0x01000100"));
			mergeSet.addRange(addr(p1, "Foo::0x0100017f"), addr(p1, "Foo::0x0100017f"));
			mergeSet.addRange(addr(p1, "Foo::0x01000180"), addr(p1, "Foo::0x01000180"));
			mergeSet.addRange(addr(p1, "Foo::0x010001ff"), addr(p1, "Foo::0x010001ff"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			AddressSet newDiffs = new AddressSet();
			newDiffs.addRange(addr(p1, "Foo::0x01000030"), addr(p1, "Foo::0x01000030"));
			newDiffs.addRange(addr(p1, "Foo::0x0100007f"), addr(p1, "Foo::0x0100007f"));
			newDiffs.addRange(addr(p1, "Foo::0x01000100"), addr(p1, "Foo::0x01000100"));
			newDiffs.addRange(addr(p1, "Foo::0x0100017f"), addr(p1, "Foo::0x0100017f"));
			assertEquals(newDiffs, programMerge.getFilteredDifferences());

			SymbolTable st = p1.getSymbolTable();
			Symbol[] symbols;
			symbols = st.getSymbols(addr(p1, "Foo::0x01000030"));
			assertEquals(1, symbols.length);
			assertEquals("Sample0030", symbols[0].getName(true));

			symbols = st.getSymbols(addr(p1, "Foo::0x0100007f"));
			assertEquals(1, symbols.length);
			assertEquals("Sample007f", symbols[0].getName(true));

			symbols = st.getSymbols(addr(p1, "Foo::0x01000080"));
			assertEquals(1, symbols.length);
			assertEquals("Other0080", symbols[0].getName(true));

			symbols = st.getSymbols(addr(p1, "Foo::0x01000100"));
			assertEquals(2, symbols.length);
			Comparator<Symbol> c = SymbolUtilities.getSymbolNameComparator();
			Arrays.sort(symbols, c);
			assertEquals("Other0100", symbols[0].getName(true));
			assertEquals("Sample0100", symbols[1].getName(true));

			symbols = st.getSymbols(addr(p1, "Foo::0x0100017f"));
			assertEquals(1, symbols.length);
			assertEquals("Sample017f", symbols[0].getName(true));

			symbols = st.getSymbols(addr(p1, "Foo::0x01000180"));
			assertEquals(1, symbols.length);
			assertEquals("Other0180", symbols[0].getName(true));

			symbols = st.getSymbols(addr(p1, "Foo::0x010001ff"));
			assertEquals(1, symbols.length);
			assertEquals("Other01ff", symbols[0].getName(true));

			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}

		ProgramDiff latestProgramDiff = new ProgramDiff(p1, mtf.getLatestProgram());
		AddressSet latestAddrSet = new AddressSet();
		latestAddrSet.addRange(addr(p1, "Foo::0x01000080"), addr(p1, "Foo::0x01000080"));
		latestAddrSet.addRange(addr(p1, "Foo::0x01000180"), addr(p1, "Foo::0x01000180"));
		latestAddrSet.addRange(addr(p1, "Foo::0x01000100"), addr(p1, "Foo::0x01000100"));
		latestAddrSet.addRange(addr(p1, "Foo::0x010001ff"), addr(p1, "Foo::0x010001ff"));
		latestProgramDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.ALL_DIFFS));
		assertEquals(latestAddrSet,
			latestProgramDiff.getDifferences(latestProgramDiff.getFilter(), null));

		ProgramDiff myProgramDiff = new ProgramDiff(p1, mtf.getPrivateProgram());
		AddressSet myAddrSet = new AddressSet();
		myAddrSet.addRange(addr(p1, "Foo::0x01000030"), addr(p1, "Foo::0x01000030"));
		myAddrSet.addRange(addr(p1, "Foo::0x0100007f"), addr(p1, "Foo::0x0100007f"));
		myAddrSet.addRange(addr(p1, "Foo::0x01000100"), addr(p1, "Foo::0x01000100"));
		myAddrSet.addRange(addr(p1, "Foo::0x0100017f"), addr(p1, "Foo::0x0100017f"));
		myProgramDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.ALL_DIFFS));
		assertEquals(myAddrSet, myProgramDiff.getDifferences(myProgramDiff.getFilter(), null));
	}

	@Test
	public void testReplaceRefSource() throws Exception {
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

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			programMerge = new ProgramMergeManager(p1, p2, null, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.REFERENCES, ProgramMergeFilter.REPLACE));
			AddressSet expectedDiffs = new AddressSet();
// For now we no longer want to detect source type differences since they can't be changed anyway.
//			expectedDiffs.addRange(addr(p1, "0x01001e81"), addr(p1, "0x01001e82"));
//			expectedDiffs.addRange(addr(p1, "0x01001ea0"), addr(p1, "0x01001ea1"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x01001e4f"), addr(p1, "0x01001efc"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			AddressSet newDiffs = new AddressSet();
			assertEquals(newDiffs, programMerge.getFilteredDifferences());

			ReferenceManager rm = p1.getReferenceManager();
			Reference[] refs;
			refs = rm.getReferencesFrom(addr(p1, "0x01001e81"));
			assertEquals(1, refs.length);
			assertEquals(SourceType.USER_DEFINED, refs[0].getSource());

			refs = rm.getReferencesFrom(addr(p1, "0x01001ea0"));
			assertEquals(1, refs.length);
			assertEquals(SourceType.IMPORTED, refs[0].getSource());

			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}

		ProgramDiff latestProgramDiff = new ProgramDiff(p1, mtf.getLatestProgram());
		AddressSet latestAddrSet = new AddressSet();
// For now we no longer want to detect source type differences since they can't be changed anyway.
//		latestAddrSet.addRange(addr(p1, "0x01001e81"), addr(p1, "0x01001e82"));
//		latestAddrSet.addRange(addr(p1, "0x01001ea0"), addr(p1, "0x01001ea1"));
		latestProgramDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.ALL_DIFFS));
		assertEquals(latestAddrSet,
			latestProgramDiff.getDifferences(latestProgramDiff.getFilter(), null));

		ProgramDiff myProgramDiff = new ProgramDiff(p1, mtf.getPrivateProgram());
		AddressSet myAddrSet = new AddressSet();
		myProgramDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.ALL_DIFFS));
		assertEquals(myAddrSet, myProgramDiff.getDifferences(myProgramDiff.getFilter(), null));

	}

	@Test
	public void testMergeFunctionLabelsWhereNoFunction() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					program.getGlobalNamespace();
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f = functionMgr.getFunctionAt(addr(program, "0x01004132"));
						assertNotNull(f);
						assertTrue(functionMgr.removeFunction(addr(program, "0x01004132")));
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
						Symbol sym = st.createLabel(addr(program, "0x01004136"), "stuff",
							SourceType.USER_DEFINED);
						assertNotNull(sym);
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

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x01001a00"), addr(p1, "0x01006500"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.SYMBOLS, ProgramMergeFilter.MERGE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x01004132"), addr(p1, "0x01004132"));
			expectedDiffs.addRange(addr(p1, "0x01004136"), addr(p1, "0x01004136"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x01004132"), addr(p1, "0x01004132"));
			mergeSet.addRange(addr(p1, "0x01004136"), addr(p1, "0x01004136"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			expectedDiffs.deleteRange(addr(p1, "0x01004136"), addr(p1, "0x01004136"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			SymbolTable st = p1.getSymbolTable();
			Symbol[] syms;
			syms = st.getSymbols(addr(p1, "0x01004132"));
			assertEquals(1, syms.length);
			assertEquals("SUB_01004132", syms[0].getName());
			assertEquals(p1.getGlobalNamespace(), syms[0].getParentNamespace());
			syms = st.getSymbols(addr(p1, "0x01004136"));
			assertEquals(1, syms.length);
			assertEquals("stuff", syms[0].getName());
			assertEquals(p1.getGlobalNamespace(), syms[0].getParentNamespace());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testMergeFunctionLabelsWhereDifferentFunction() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f;
						f = functionMgr.getFunctionAt(addr(program, "0x01004132"));
						assertNotNull(f);
						assertTrue(functionMgr.removeFunction(addr(program, "0x01004132")));
						String name =
							SymbolUtilities.getDefaultFunctionName(addr(program, "0x01004136"));
						AddressSet body = new AddressSet();
						body.addRange(addr(program, "0x01004136"), addr(program, "0x01004149"));
						f = functionMgr.createFunction(name, addr(program, "0x01004136"), body,
							SourceType.USER_DEFINED);
						assertNotNull(f);
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
						Symbol sym = st.createLabel(
							addr(program, "0x01004140"), "stuff", program.getFunctionManager()
								.getFunctionContaining(addr(program, "0x01004140")),
							SourceType.USER_DEFINED);
						assertNotNull(sym);
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

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x01001a00"), addr(p1, "0x01006500"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.SYMBOLS, ProgramMergeFilter.MERGE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x01004132"), addr(p1, "0x01004132"));
			expectedDiffs.addRange(addr(p1, "0x01004136"), addr(p1, "0x01004136"));
			expectedDiffs.addRange(addr(p1, "0x01004140"), addr(p1, "0x01004140"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x01004132"), addr(p1, "0x01004132"));
			mergeSet.addRange(addr(p1, "0x01004136"), addr(p1, "0x01004136"));
			mergeSet.addRange(addr(p1, "0x01004140"), addr(p1, "0x01004140"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			SymbolTable st = p1.getSymbolTable();
			Symbol[] syms;
			syms = st.getSymbols(addr(p1, "0x01004132"));
			assertEquals(1, syms.length);
			assertEquals("SUB_01004132", syms[0].getName());
			assertEquals(p1.getGlobalNamespace(), syms[0].getParentNamespace());
			syms = st.getSymbols(addr(p1, "0x01004140"));
			assertEquals(1, syms.length);
			assertEquals("stuff", syms[0].getName());
			Function f = p1.getFunctionManager().getFunctionContaining(addr(p1, "0x01004140"));
			assertEquals(f, syms[0].getParentNamespace());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testReplaceFunctionLabelsWhereDifferentFunction() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// P1 program
				int txId = program.startTransaction("Modify Program 1");
				boolean commit = false;
				try {
					FunctionManager functionMgr = program.getFunctionManager();
					try {
						Function f;
						f = functionMgr.getFunctionAt(addr(program, "0x01004132"));
						assertNotNull(f);
						assertTrue(functionMgr.removeFunction(addr(program, "0x01004132")));
						String name =
							SymbolUtilities.getDefaultFunctionName(addr(program, "0x01004136"));
						AddressSet body = new AddressSet();
						body.addRange(addr(program, "0x01004136"), addr(program, "0x01004149"));
						f = functionMgr.createFunction(name, addr(program, "0x01004136"), body,
							SourceType.USER_DEFINED);
						assertNotNull(f);
						f.setName("Foo1234", SourceType.USER_DEFINED);
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
					FunctionManager functionManager = program.getFunctionManager();
					Function f = functionManager.getFunctionContaining(addr(program, "0x01004140"));
					try {
						f.setName("Bar1234", SourceType.USER_DEFINED);
						Symbol sym = st.createLabel(addr(program, "0x01004132"), "doit", f,
							SourceType.USER_DEFINED);
						assertNotNull(sym);
						sym = st.createLabel(addr(program, "0x01004140"), "stuff", f,
							SourceType.USER_DEFINED);
						assertNotNull(sym);
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

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x01001a00"), addr(p1, "0x01006500"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.SYMBOLS, ProgramMergeFilter.REPLACE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x01004132"), addr(p1, "0x01004132"));
			expectedDiffs.addRange(addr(p1, "0x01004136"), addr(p1, "0x01004136"));
			expectedDiffs.addRange(addr(p1, "0x01004140"), addr(p1, "0x01004140"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x1004130"), addr(p1, "0x1004160"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			SymbolTable st = p1.getSymbolTable();
			Symbol[] syms;
			syms = st.getSymbols(addr(p1, "0x01004132"));
			assertEquals(2, syms.length);
			assertEquals("Bar1234", syms[0].getName());
			assertEquals(p1.getGlobalNamespace(), syms[0].getParentNamespace());
			assertEquals("doit", syms[1].getName());
			assertEquals(p1.getGlobalNamespace(), syms[1].getParentNamespace());
			syms = st.getSymbols(addr(p1, "0x01004140"));
			assertEquals(1, syms.length);
			assertEquals("stuff", syms[0].getName());
			Function f = p1.getFunctionManager().getFunctionContaining(addr(p1, "0x01004140"));
			assertEquals(f, syms[0].getParentNamespace());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testReplaceDelaySlotInstructions() throws Exception {
		mtf.initialize("r4000", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// P2 program
				int txId = program.startTransaction("Modify Program 2");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					Instruction instr = listing.getInstructionAt(addr(program, "0x808c"));
					instr.setFlowOverride(FlowOverride.BRANCH);
					instr = listing.getInstructionAt(addr(program, "0x8090"));
					instr.setFallThrough(null);
					instr = listing.getInstructionAt(addr(program, "0x8098"));
					instr.setFallThrough(null);
					instr = listing.getInstructionAt(addr(program, "0x80b4"));
					instr.setFlowOverride(FlowOverride.CALL);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		p1 = mtf.getResultProgram();
		p2 = mtf.getPrivateProgram();

		int txId = p1.startTransaction("Merge into Program 1");
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x8080"), addr(p1, "0x80d0"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			//programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.ALL, ProgramMergeFilter.REPLACE));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "0x808c"), addr(p1, "0x8093"));
			expectedDiffs.addRange(addr(p1, "0x8098"), addr(p1, "0x809b"));
			expectedDiffs.addRange(addr(p1, "0x80b4"), addr(p1, "0x80b7"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			assertTrue(programMerge.merge(expectedDiffs, TaskMonitorAdapter.DUMMY_MONITOR));

		}
		finally {
			p1.endTransaction(txId, true);
		}

		Listing resultListing = p1.getListing();
		Listing sourceListing = p2.getListing();

		Instruction sourceInstr = sourceListing.getInstructionAt(addr(p1, "0x808c"));
		Instruction resultInstr = resultListing.getInstructionAt(addr(p1, "0x808c"));
		assertNotNull(resultInstr);
		assertEquals(sourceInstr.getPrototype(), resultInstr.getPrototype());
		assertEquals(sourceInstr.getFlowOverride(), resultInstr.getFlowOverride());
		assertEquals(sourceInstr.getFallThrough(), resultInstr.getFallThrough());

		sourceInstr = sourceListing.getInstructionAt(addr(p1, "0x8090"));
		resultInstr = resultListing.getInstructionAt(addr(p1, "0x8090"));
		assertNotNull(resultInstr);
		assertEquals(sourceInstr.getPrototype(), resultInstr.getPrototype());
		assertEquals(sourceInstr.getFlowOverride(), resultInstr.getFlowOverride());
		assertEquals(sourceInstr.getFallThrough(), resultInstr.getFallThrough());

		sourceInstr = sourceListing.getInstructionAt(addr(p1, "0x8094"));
		resultInstr = resultListing.getInstructionAt(addr(p1, "0x8094"));
		assertNotNull(resultInstr);
		assertEquals(sourceInstr.getPrototype(), resultInstr.getPrototype());
		assertEquals(sourceInstr.getFlowOverride(), resultInstr.getFlowOverride());
		assertEquals(sourceInstr.getFallThrough(), resultInstr.getFallThrough());

		sourceInstr = sourceListing.getInstructionAt(addr(p1, "0x8098"));
		resultInstr = resultListing.getInstructionAt(addr(p1, "0x8098"));
		assertNotNull(resultInstr);
		assertEquals(sourceInstr.getPrototype(), resultInstr.getPrototype());
		assertEquals(sourceInstr.getFlowOverride(), resultInstr.getFlowOverride());
		assertEquals(sourceInstr.getFallThrough(), resultInstr.getFallThrough());

		sourceInstr = sourceListing.getInstructionAt(addr(p1, "0x80b4"));
		resultInstr = resultListing.getInstructionAt(addr(p1, "0x80b4"));
		assertNotNull(resultInstr);
		assertEquals(sourceInstr.getPrototype(), resultInstr.getPrototype());
		assertEquals(sourceInstr.getFlowOverride(), resultInstr.getFlowOverride());
		assertEquals(sourceInstr.getFallThrough(), resultInstr.getFallThrough());

		sourceInstr = sourceListing.getInstructionAt(addr(p1, "0x80b8"));
		resultInstr = resultListing.getInstructionAt(addr(p1, "0x80b8"));
		assertNotNull(resultInstr);
		assertEquals(sourceInstr.getPrototype(), resultInstr.getPrototype());
		assertEquals(sourceInstr.getFlowOverride(), resultInstr.getFlowOverride());
		assertEquals(sourceInstr.getFallThrough(), resultInstr.getFallThrough());

	}

	@Test
	public void testMergeFunctionWithForcedIndirectParameter() throws Exception {

		mtf.initialize("DiffTestPgm1_X86_64", new ProgramModifierListener() {

			// should apply diff on parameter data type.

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

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x1000"), addr(p1, "0x1000"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.MERGE));
			AddressSet expectedDiffsBefore = new AddressSet();
			expectedDiffsBefore.addRange(addr(p1, "0x1000"), addr(p1, "0x1000"));
			assertEquals(expectedDiffsBefore, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x1000"), addr(p1, "0x1000"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			AddressSet expectedDiffsAfter = new AddressSet();
			assertEquals(expectedDiffsAfter, programMerge.getFilteredDifferences());

			SymbolTable st = p1.getSymbolTable();
			Symbol[] syms;
			syms = st.getSymbols(addr(p1, "0x1000"));
			assertEquals(1, syms.length);
			assertEquals("bob", syms[0].getName());
			assertEquals(p1.getGlobalNamespace(), syms[0].getParentNamespace());

			Function func = getFunction(p1, "0x1000");
			assertEquals("void bob(struct stuff)", func.getPrototypeString(true, false));
			Parameter parameter = func.getParameter(0);
			assertEquals("[struct * stuff@RCX:8 (ptr)]", parameter.toString());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testMergeFunctionReplacesForcedIndirectParameter() throws Exception {

		mtf.initialize("DiffTestPgm1_X86_64", new ProgramModifierListener() {

			// should apply diff on parameter data type.

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
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

			@Override
			public void modifyPrivate(ProgramDB program) {
				// Forced indirect for the return.
				int txId = program.startTransaction("Modify My Program");
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
		});

		p1 = mtf.getResultProgram();
		p2 = mtf.getPrivateProgram();

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x1000"), addr(p1, "0x1000"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.MERGE));
			AddressSet expectedDiffsBefore = new AddressSet();
			expectedDiffsBefore.addRange(addr(p1, "0x1000"), addr(p1, "0x1000"));
			assertEquals(expectedDiffsBefore, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x1000"), addr(p1, "0x1000"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			AddressSet expectedDiffsAfter = new AddressSet();
			assertEquals(expectedDiffsAfter, programMerge.getFilteredDifferences());

			SymbolTable st = p1.getSymbolTable();
			Symbol[] syms;
			syms = st.getSymbols(addr(p1, "0x1000"));
			assertEquals(1, syms.length);
			assertEquals("bob", syms[0].getName());
			assertEquals(p1.getGlobalNamespace(), syms[0].getParentNamespace());

			Function func = getFunction(p1, "0x1000");
			assertEquals("void bob(byte stuff)", func.getPrototypeString(true, false));
			Parameter parameter = func.getParameter(0);
			assertEquals("[byte stuff@CL:1]", parameter.toString());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testMergeFunctionWithForcedIndirectOnReturnWithAutoParam() throws Exception {

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			// should applyt diff on return type and jim vs. bob parameter name, with return ptr auto-param

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
				Function func = getFunction(program, "0x1002249");
				assertEquals("undefined4 FUN_01002249(MyClass * this, int jim)",
					func.getPrototypeString(false, false));
				assertEquals(2, func.getParameterCount());
				Parameter parameter = func.getParameter(0);
				assertEquals("[MyClass * this@ECX:4 (auto)]", parameter.toString());
				parameter = func.getParameter(1);
				assertEquals("[int jim@Stack[0x4]:4]", parameter.toString());
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
				Function func = getFunction(program, "0x1002249");
				assertEquals("struct * FUN_01002249(struct * __return_storage_ptr__, int bob)",
					func.getPrototypeString(false, false));
				assertEquals(2, func.getParameterCount());
				Parameter parameter = func.getParameter(0);
				assertEquals("[struct * __return_storage_ptr__@Stack[0x4]:4 (auto)]",
					parameter.toString());
				parameter = func.getParameter(1);
				assertEquals("[int bob@Stack[0x8]:4]", parameter.toString());
			}
		});

		p1 = mtf.getResultProgram();
		p2 = mtf.getPrivateProgram();

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x1002249"), addr(p1, "0x1002249"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.MERGE));
			AddressSet expectedDiffsBefore = new AddressSet();
			expectedDiffsBefore.addRange(addr(p1, "0x1002249"), addr(p1, "0x1002249"));
			assertEquals(expectedDiffsBefore, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x1002249"), addr(p1, "0x1002249"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			AddressSet expectedDiffsAfter = new AddressSet();
			assertEquals(expectedDiffsAfter, programMerge.getFilteredDifferences());

			Function func = getFunction(p1, "0x1002249");
			assertEquals("struct * FUN_01002249(struct * __return_storage_ptr__, int bob)",
				func.getPrototypeString(false, false));
			assertEquals(2, func.getParameterCount());
			Parameter parameter = func.getParameter(0);
			assertEquals("[struct * __return_storage_ptr__@Stack[0x4]:4 (auto)]",
				parameter.toString());
			parameter = func.getParameter(1);
			assertEquals("[int bob@Stack[0x8]:4]", parameter.toString());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testMergeFunctionReplacingForcedIndirectOnReturnWithAutoParam() throws Exception {

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			// should apply diff on return type and jim vs. bob parameter name, with return ptr auto-param

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
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
				Function func = getFunction(program, "0x1002249");
				assertEquals("struct * FUN_01002249(struct * __return_storage_ptr__, int bob)",
					func.getPrototypeString(false, false));
				assertEquals(2, func.getParameterCount());
				Parameter parameter = func.getParameter(0);
				assertEquals("[struct * __return_storage_ptr__@Stack[0x4]:4 (auto)]",
					parameter.toString());
				parameter = func.getParameter(1);
				assertEquals("[int bob@Stack[0x8]:4]", parameter.toString());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// Forced indirect for the return.
				int txId = program.startTransaction("Modify My Program");
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
				Function func = getFunction(program, "0x1002249");
				assertEquals("undefined4 FUN_01002249(MyClass * this, int jim)",
					func.getPrototypeString(false, false));
				assertEquals(2, func.getParameterCount());
				Parameter parameter = func.getParameter(0);
				assertEquals("[MyClass * this@ECX:4 (auto)]", parameter.toString());
				parameter = func.getParameter(1);
				assertEquals("[int jim@Stack[0x4]:4]", parameter.toString());
			}
		});

		p1 = mtf.getResultProgram();
		p2 = mtf.getPrivateProgram();

		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "0x1002249"), addr(p1, "0x1002249"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.MERGE));
			AddressSet expectedDiffsBefore = new AddressSet();
			expectedDiffsBefore.addRange(addr(p1, "0x1002249"), addr(p1, "0x1002249"));
			assertEquals(expectedDiffsBefore, programMerge.getFilteredDifferences());

			AddressSet mergeSet = new AddressSet();
			mergeSet.addRange(addr(p1, "0x1002249"), addr(p1, "0x1002249"));
			programMerge.merge(mergeSet, TaskMonitorAdapter.DUMMY_MONITOR);

			AddressSet expectedDiffsAfter = new AddressSet();
			assertEquals(expectedDiffsAfter, programMerge.getFilteredDifferences());

			Function func = getFunction(p1, "0x1002249");
			assertEquals("undefined4 FUN_01002249(MyClass * this, int jim)",
				func.getPrototypeString(false, false));
			assertEquals(2, func.getParameterCount());
			Parameter parameter = func.getParameter(0);
			assertEquals("[MyClass * this@ECX:4 (auto)]", parameter.toString());
			parameter = func.getParameter(1);
			assertEquals("[int jim@Stack[0x4]:4]", parameter.toString());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}
	}

	@Test
	public void testMergeOverlayOrderNoConflict() throws Exception {
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
		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "SomeOverlay::01001630"),
				addr(p1, "SomeOverlay::0100182f"));
			setToDiff.addRange(addr(p2, "SomeOverlay::01001830"),
				addr(p2, "SomeOverlay::0100192f"));
			setToDiff.addRange(addr(p1, "OtherOverlay::01001630"),
				addr(p1, "OtherOverlay::0100192f"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "SomeOverlay::01001630"),
				addr(p1, "SomeOverlay::01001630"));
			expectedDiffs.addRange(addr(p1, "OtherOverlay::01001646"),
				addr(p1, "OtherOverlay::01001646"));
			expectedDiffs.addRange(addr(p1, "OtherOverlay::01001866"),
				addr(p1, "OtherOverlay::01001866"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.SYMBOLS, ProgramMergeFilter.MERGE));
			programMerge.merge(expectedDiffs, TaskMonitorAdapter.DUMMY_MONITOR);

			AddressSet expectedPostMergeDiffs = new AddressSet();
			expectedPostMergeDiffs.addRange(addr(p1, "SomeOverlay::01001630"),
				addr(p1, "SomeOverlay::01001630"));
			expectedPostMergeDiffs.addRange(addr(p1, "OtherOverlay::01001866"),
				addr(p1, "OtherOverlay::01001866"));
			assertEquals(expectedPostMergeDiffs, programMerge.getFilteredDifferences());

			assertEquals(expectedPostMergeDiffs, programMerge.getFilteredDifferences());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}

		SymbolTable resultSymTab = p1.getSymbolTable();

		Symbol[] symbols = resultSymTab.getSymbols(addr(p1, "SomeOverlay::01001630"));
		assertEquals(1, symbols.length);
		assertEquals("OVL1630", symbols[0].getName());

		symbols = resultSymTab.getSymbols(addr(p1, "SomeOverlay::01001889"));
		assertEquals(0, symbols.length); // Not part of the merge set.

		symbols = resultSymTab.getSymbols(addr(p1, "OtherOverlay::01001646"));
		assertEquals(1, symbols.length);
		assertEquals("OVL1646", symbols[0].getName());

		symbols = resultSymTab.getSymbols(addr(p1, "OtherOverlay::01001866"));
		assertEquals(1, symbols.length);
		assertEquals("OVL1866", symbols[0].getName());
	}

	@Test
	public void testReplaceOverlayOrderNoConflict() throws Exception {
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
		int txId = p1.startTransaction("Replace in Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "SomeOverlay::01001630"),
				addr(p1, "SomeOverlay::0100182f"));
			setToDiff.addRange(addr(p2, "SomeOverlay::01001830"),
				addr(p2, "SomeOverlay::0100192f"));
			setToDiff.addRange(addr(p1, "OtherOverlay::01001630"),
				addr(p1, "OtherOverlay::0100192f"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "SomeOverlay::01001630"),
				addr(p1, "SomeOverlay::01001630"));
			expectedDiffs.addRange(addr(p1, "OtherOverlay::01001646"),
				addr(p1, "OtherOverlay::01001646"));
			expectedDiffs.addRange(addr(p1, "OtherOverlay::01001866"),
				addr(p1, "OtherOverlay::01001866"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.SYMBOLS, ProgramMergeFilter.REPLACE));
			programMerge.merge(expectedDiffs, TaskMonitorAdapter.DUMMY_MONITOR);

			AddressSet expectedPostMergeDiffs = new AddressSet();
			expectedPostMergeDiffs.addRange(addr(p1, "OtherOverlay::01001866"),
				addr(p1, "OtherOverlay::01001866"));
			assertEquals(expectedPostMergeDiffs, programMerge.getFilteredDifferences());

			assertEquals(expectedPostMergeDiffs, programMerge.getFilteredDifferences());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}

		SymbolTable resultSymTab = p1.getSymbolTable();

		Symbol[] symbols = resultSymTab.getSymbols(addr(p1, "SomeOverlay::01001630"));
		assertEquals(0, symbols.length);

		symbols = resultSymTab.getSymbols(addr(p1, "SomeOverlay::01001889"));
		assertEquals(0, symbols.length); // Not part of the merge set.

		symbols = resultSymTab.getSymbols(addr(p1, "OtherOverlay::01001646"));
		assertEquals(1, symbols.length);
		assertEquals("OVL1646", symbols[0].getName());

		symbols = resultSymTab.getSymbols(addr(p1, "OtherOverlay::01001866"));
		assertEquals(1, symbols.length);
		assertEquals("OVL1866", symbols[0].getName());
	}

	@Test
	public void testMergeOverlayOrderWithConflict() throws Exception {
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
						st.createLabel(addr(program, "SomeOverlay::01001630"), "OVL1630_Latest",
							SourceType.USER_DEFINED);
						st.createLabel(addr(program, "OtherOverlay::01001646"), "OVL1646_Latest",
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
						st.createLabel(addr(program, "SomeOverlay::01001630"), "OVL1630_Private",
							SourceType.USER_DEFINED);
						st.createLabel(addr(program, "OtherOverlay::01001646"), "OVL1646_Private",
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
		int txId = p1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "SomeOverlay::01001630"),
				addr(p1, "SomeOverlay::0100182f"));
			setToDiff.addRange(addr(p2, "SomeOverlay::01001830"),
				addr(p2, "SomeOverlay::0100192f"));
			setToDiff.addRange(addr(p1, "OtherOverlay::01001630"),
				addr(p1, "OtherOverlay::0100192f"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "SomeOverlay::01001630"),
				addr(p1, "SomeOverlay::01001630"));
			expectedDiffs.addRange(addr(p1, "OtherOverlay::01001646"),
				addr(p1, "OtherOverlay::01001646"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.SYMBOLS, ProgramMergeFilter.MERGE));
			programMerge.merge(expectedDiffs, TaskMonitorAdapter.DUMMY_MONITOR);

			AddressSet expectedPostMergeDiffs = new AddressSet();
			expectedPostMergeDiffs.addRange(addr(p1, "SomeOverlay::01001630"),
				addr(p1, "SomeOverlay::01001630"));
			expectedPostMergeDiffs.addRange(addr(p1, "OtherOverlay::01001646"),
				addr(p1, "OtherOverlay::01001646"));
			assertEquals(expectedPostMergeDiffs, programMerge.getFilteredDifferences());

			assertEquals(expectedPostMergeDiffs, programMerge.getFilteredDifferences());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}

		SymbolTable resultSymTab = p1.getSymbolTable();

		Symbol[] symbols = resultSymTab.getSymbols(addr(p1, "SomeOverlay::01001630"));
		assertEquals(2, symbols.length);
		assertEquals("OVL1630_Latest", symbols[0].getName());
		assertEquals("OVL1630_Private", symbols[1].getName());

		symbols = resultSymTab.getSymbols(addr(p1, "OtherOverlay::01001646"));
		assertEquals(2, symbols.length);
		assertEquals("OVL1646_Latest", symbols[0].getName());
		assertEquals("OVL1646_Private", symbols[1].getName());
	}

	@Test
	public void testReplaceOverlayOrderWithConflict() throws Exception {
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

						st.createLabel(addr(program, "SomeOverlay::01001630"), "OVL1630_Latest",
							SourceType.USER_DEFINED);
						st.createLabel(addr(program, "OtherOverlay::01001646"), "OVL1646_Latest",
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

						st.createLabel(addr(program, "SomeOverlay::01001630"), "OVL1630_Private",
							SourceType.USER_DEFINED);
						st.createLabel(addr(program, "OtherOverlay::01001646"), "OVL1646_Private",
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
		int txId = p1.startTransaction("Replace in Program 1");
		boolean commit = false;
		try {
			AddressSet setToDiff = new AddressSet();
			setToDiff.addRange(addr(p1, "SomeOverlay::01001630"),
				addr(p1, "SomeOverlay::0100182f"));
			setToDiff.addRange(addr(p2, "SomeOverlay::01001830"),
				addr(p2, "SomeOverlay::0100192f"));
			setToDiff.addRange(addr(p1, "OtherOverlay::01001630"),
				addr(p1, "OtherOverlay::0100192f"));
			programMerge =
				new ProgramMergeManager(p1, p2, setToDiff, TaskMonitorAdapter.DUMMY_MONITOR);

			programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS));
			AddressSet expectedDiffs = new AddressSet();
			expectedDiffs.addRange(addr(p1, "SomeOverlay::01001630"),
				addr(p1, "SomeOverlay::01001630"));
			expectedDiffs.addRange(addr(p1, "OtherOverlay::01001646"),
				addr(p1, "OtherOverlay::01001646"));
			assertEquals(expectedDiffs, programMerge.getFilteredDifferences());

			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.SYMBOLS, ProgramMergeFilter.REPLACE));
			programMerge.merge(expectedDiffs, TaskMonitorAdapter.DUMMY_MONITOR);

			AddressSet expectedPostMergeDiffs = new AddressSet();
			assertEquals(expectedPostMergeDiffs, programMerge.getFilteredDifferences());

			assertEquals(expectedPostMergeDiffs, programMerge.getFilteredDifferences());
			commit = true;
		}
		finally {
			p1.endTransaction(txId, commit);
		}

		SymbolTable resultSymTab = p1.getSymbolTable();

		Symbol[] symbols = resultSymTab.getSymbols(addr(p1, "SomeOverlay::01001630"));
		assertEquals(1, symbols.length);
		assertEquals("OVL1630_Private", symbols[0].getName());

		symbols = resultSymTab.getSymbols(addr(p1, "OtherOverlay::01001646"));
		assertEquals(1, symbols.length);
		assertEquals("OVL1646_Private", symbols[0].getName());
	}

	protected Function getFunction(Program program, String address) {
		Address addr = addr(program, address);
		return program.getFunctionManager().getFunctionAt(addr);
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
