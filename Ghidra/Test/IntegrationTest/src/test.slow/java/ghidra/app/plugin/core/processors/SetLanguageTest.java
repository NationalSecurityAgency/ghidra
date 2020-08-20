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
package ghidra.app.plugin.core.processors;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import javax.swing.tree.TreePath;

import org.junit.*;

import docking.AbstractErrDialog;
import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.widgets.MultiLineLabel;
import docking.widgets.OptionDialog;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.main.datatree.*;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.plugin.importer.NewLanguagePanel;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;

public class SetLanguageTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private FrontEndTool frontEndTool;

	private DockingActionIf setLanguageAction;
	private GTreeNode notepadNode;
	private DomainFile notepadFile;
	private GTreeNode xyzFolderNode;

	private AddressFactory addrFactory;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();

		setErrorGUIEnabled(true);
		frontEndTool = env.getFrontEndTool();
		env.showFrontEndTool();

		setLanguageAction = getAction(frontEndTool, "LanguageProviderPlugin", "Set Language");

		// NOTE: Only test translation from a supported language to another supported language

// TODO: Change test data to a supported case (e.g., MIPS-32 to MIPS-64)

		DomainFolder rootFolder = env.getProject().getProjectData().getRootFolder();

		ProgramBuilder builder = new ProgramBuilder("notepad", "x86:LE:32:default");
		Program p = builder.getProgram();

		assertEquals(new LanguageID("x86:LE:32:default"), p.getLanguageID());
		rootFolder.createFile("notepad", p, TaskMonitor.DUMMY);
		env.release(p);
		builder.dispose();

		rootFolder.createFolder("XYZ");
		GTree tree = findComponent(frontEndTool.getToolFrame(), GTree.class);
		waitForTree(tree);

		GTreeNode rootNode = tree.getViewRoot();
		xyzFolderNode = rootNode.getChild(0);
		notepadNode = rootNode.getChild(1);
		notepadFile = ((DomainFileNode) notepadNode).getDomainFile();

		waitForSwing();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testActionEnablement() throws Exception {
		assertTrue(setLanguageAction.isEnabled());
		assertFalse(setLanguageAction.isEnabledForContext(createProjectDataContext(xyzFolderNode)));
		assertTrue(setLanguageAction.isEnabledForContext(createProjectDataContext(notepadNode)));
	}

	private Address addr(String address) {
		return addrFactory.getAddress(address);
	}

	private void startSetLanguage(LanguageID languageID, CompilerSpecID compilerSpecID,
			boolean isFailureCase) throws Exception {
		if (languageID == null) {
			throw new RuntimeException("languageID == null not allowed");
		}
		if (compilerSpecID == null) {
			throw new RuntimeException("compilerSpecID == null not allowed");
		}

		// this triggers a modal dialog
		runSwing(() -> {
			ActionContext context = createProjectDataContext(notepadNode);
			assertTrue(setLanguageAction.isEnabledForContext(context));
			setLanguageAction.actionPerformed(context);
		}, false);

		OptionDialog confirmDlg = waitForDialogComponent(OptionDialog.class);
		assertNotNull(confirmDlg);
		MultiLineLabel msgLabel = findComponent(confirmDlg, MultiLineLabel.class);
		assertNotNull(msgLabel);
		assertTrue(msgLabel.getLabel().indexOf("Setting the language can not be undone") >= 0);
		assertTrue(msgLabel.getLabel().indexOf("make a copy") > 0);

		pressButtonByText(confirmDlg, "Ok");

		SetLanguageDialog dlg = waitForDialogComponent(SetLanguageDialog.class);
		assertNotNull(dlg);
		NewLanguagePanel languagePanel =
			(NewLanguagePanel) getInstanceField("selectLangPanel", dlg);
		assertNotNull(languagePanel);

		waitForSwing();

		runSwing(() -> {
			NewLanguagePanel selectLangPanel =
				(NewLanguagePanel) getInstanceField("selectLangPanel", dlg);
			selectLangPanel.setSelectedLcsPair(
				new LanguageCompilerSpecPair(languageID, compilerSpecID));
		}, true);

		waitForSwing();

		pressButtonByText(dlg, "OK");

		if (!isFailureCase) {
			confirmDlg = waitForDialogComponent(OptionDialog.class);
			assertNotNull(confirmDlg);
			msgLabel = findComponent(confirmDlg, MultiLineLabel.class);
			assertNotNull(msgLabel);
			assertTrue(msgLabel.getLabel().indexOf("Would you like to Save") >= 0);

			pressButtonByText(confirmDlg, "Save");
		}
	}

	private ActionContext createProjectDataContext(GTreeNode node) {
		TreePath[] selectionPaths = { node.getTreePath() };

		List<DomainFile> fileList = new ArrayList<>();
		List<DomainFolder> folderList = new ArrayList<>();
		if (node instanceof DomainFileNode) {
			fileList.add(((DomainFileNode) node).getDomainFile());
		}
		else {
			folderList.add(((DomainFolderNode) node).getDomainFolder());
		}

		return new FrontEndProjectTreeContext(null, null, selectionPaths, folderList, fileList,
			(DataTree) node.getTree(), true);
	}

	@Test
	public void testReplaceLanguage() throws Exception {

		startSetLanguage(new LanguageID("x86:LE:32:System Management Mode"),
			new CompilerSpecID("default"), false);

		waitForTasks();

		Program p = (Program) notepadFile.getDomainObject(this, false, false, TaskMonitor.DUMMY);
		assertNotNull(p);
		try {
			assertEquals(new LanguageID("x86:LE:32:System Management Mode"),
				p.getLanguage().getLanguageID());

			// TODO: Other checks needed ??

		}
		finally {
			p.release(this);
		}
	}

	@Test
	public void testReplaceLanguageFailure() throws Exception {

		startSetLanguage(new LanguageID("8051:BE:16:default"), new CompilerSpecID("default"), true);

		AbstractErrDialog d = waitForErrorDialog();
		assertTrue(d.getMessage().contains("Language translation not supported"));
		close(d);
		closeAllWindows();
	}

	@Test
	public void testReplaceLanguage2() throws Exception {

		Program p = (Program) notepadFile.getDomainObject(this, false, false, TaskMonitor.DUMMY);
		try {
			int txId = p.startTransaction("set Language");
			addrFactory = p.getAddressFactory();
			ProgramContext pc = p.getProgramContext();
			Register ax = pc.getRegister("AX");
			Register ebp = pc.getRegister("EBP");
			Register ebx = pc.getRegister("EBX");
			pc.setValue(ax, addr("0x1001000"), addr("0x1001000"), BigInteger.valueOf(0x1234));
			pc.setValue(ebp, addr("0x1001000"), addr("0x1001000"), BigInteger.valueOf(0x12345678));
			pc.setValue(ebx, addr("0x1001000"), addr("0x1001000"), BigInteger.valueOf(0x12345678));
			assertEquals(0x1234, pc.getValue(ax, addr("0x1001000"), false).longValue());
			assertEquals(0x12345678, pc.getValue(ebp, addr("0x1001000"), false).longValue());
			assertEquals(0x12345678, pc.getValue(ebx, addr("0x1001000"), false).longValue());
			p.endTransaction(txId, true);

			p.save(null, TaskMonitor.DUMMY);
		}
		finally {
			p.release(this);
		}

		startSetLanguage(new LanguageID("x86:LE:32:default"), new CompilerSpecID("gcc"), false);
		waitForTasks();

		p = (Program) notepadFile.getDomainObject(this, true, false, TaskMonitor.DUMMY);
		try {
			addrFactory = p.getAddressFactory();
			ProgramContext pc = p.getProgramContext();
			Register ax = pc.getRegister("AX");
			Register ebp = pc.getRegister("EBP");
			Register ebx = pc.getRegister("EBX");
			assertEquals(0x1234, pc.getValue(ax, addr("0x1001000"), false).longValue());
			assertEquals(0x12345678, pc.getValue(ebp, addr("0x1001000"), false).longValue());
			assertEquals(0x12345678, pc.getValue(ebx, addr("0x1001000"), false).longValue());
		}
		finally {
			p.release(this);
		}
	}

	@Test
	public void testReplaceLanguage3() throws Exception {

		Program p = (Program) notepadFile.getDomainObject(this, false, false, TaskMonitor.DUMMY);
		addrFactory = p.getAddressFactory();
		ProgramContext pc = p.getProgramContext();
		Register eax = pc.getRegister("EAX");
		Register esi = pc.getRegister("ESI");
		Register edi = pc.getRegister("EDI");
		try {
			int txId = p.startTransaction("set Language");

			Function f = p.getListing()
					.createFunction("BOB", addr("0x10041a8"),
						new AddressSet(addr("0x10041a8"), addr("0x10041c0")),
						SourceType.USER_DEFINED);
			f.setCustomVariableStorage(true);
			ParameterImpl param = new ParameterImpl("PARAM_ONE", null, eax, p);
			f.addParameter(param, SourceType.USER_DEFINED);
			LocalVariableImpl local1 = new LocalVariableImpl("LOCAL_ONE", 0, null, esi, p);
			LocalVariableImpl local2 = new LocalVariableImpl("LOCAL_TWO", 0, null, edi, p);

			f.addLocalVariable(local1, SourceType.USER_DEFINED);
			f.addLocalVariable(local2, SourceType.USER_DEFINED);

			p.getReferenceManager()
					.addRegisterReference(addr("0x10041b2"), 0, esi, RefType.DATA,
						SourceType.USER_DEFINED);
			p.getReferenceManager()
					.addRegisterReference(addr("0x10041b3"), 0, edi, RefType.DATA,
						SourceType.USER_DEFINED);

			p.endTransaction(txId, true);

			p.save(null, TaskMonitor.DUMMY);
		}
		finally {
			p.release(this);
		}

		startSetLanguage(new LanguageID("x86:LE:32:default"), new CompilerSpecID("gcc"), false);
		waitForTasks();

		p = (Program) notepadFile.getDomainObject(this, true, false, TaskMonitor.DUMMY);
		try {
			addrFactory = p.getAddressFactory();

			Function fun = p.getListing().getFunctionAt(addr("0x10041a8"));
			Parameter[] params = fun.getParameters();
			assertEquals(1, params.length);
			assertEquals("PARAM_ONE", params[0].getName());
			assertTrue(params[0].isRegisterVariable());
			assertEquals(eax, params[0].getRegister());

			Variable[] locals = fun.getLocalVariables();
			assertEquals(2, locals.length);
			assertEquals("LOCAL_ONE", locals[0].getName());
			assertEquals("LOCAL_TWO", locals[1].getName());
			assertTrue(params[0].isRegisterVariable());
			assertEquals(esi, locals[0].getRegister());
			assertEquals(edi, locals[1].getRegister());
		}
		finally {
			p.release(this);
		}
	}
}
