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
package ghidra.app.plugin.core.label;

import static org.junit.Assert.*;

import javax.swing.JComponent;
import javax.swing.JTable;
import javax.swing.table.TableModel;

import org.junit.*;

import docking.ActionContext;
import docking.DialogComponentProvider;
import docking.action.DockingActionIf;
import generic.test.TestUtils;
import ghidra.app.LocationCallback;
import ghidra.app.SampleLocationGenerator;
import ghidra.app.context.ListingActionContext;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.symbol.CodeSymbol;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.test.*;

public class LabelActionTest extends AbstractGhidraHeadedIntegrationTest
		implements LocationCallback {
	private static final String ADD_LABEL = "Add Label";
	private static final String EDIT_LABEL = "Edit Label";
	private static final String EDIT_EXTERNAL_LOC = "Edit External Location";
	private static final String REMOVE_LABEL = "Remove Label";
	private static final String SET_LABEL = "Set Operand Label";

	private Program program;
	private TestEnv env;
	private PluginTool tool;

	private DockingActionIf addLabel;
	private DockingActionIf editLabel;
	private DockingActionIf editExternalLocation;
	private DockingActionIf removeLabel;
	private DockingActionIf setLabel;
	private CodeBrowserPlugin cb;
	private LabelMgrPlugin labelMgrPlugin;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(LabelMgrPlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		labelMgrPlugin = env.getPlugin(LabelMgrPlugin.class);
		cb = env.getPlugin(CodeBrowserPlugin.class);

		ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder();
		program = builder.getProgram();

		addLabel = getAction(labelMgrPlugin, ADD_LABEL);
		editLabel = getAction(labelMgrPlugin, EDIT_LABEL);
		editExternalLocation = getAction(labelMgrPlugin, EDIT_EXTERNAL_LOC);
		removeLabel = getAction(labelMgrPlugin, REMOVE_LABEL);
		setLabel = getAction(labelMgrPlugin, SET_LABEL);

		env.showTool();
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	@Test
	public void testSetLabelActionEnabled() {
		Address addr = program.getMinAddress().getNewAddress(0x0100416c);
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program);
		ReferenceManager refMgr = program.getReferenceManager();

		Reference ref = refMgr.getPrimaryReferenceFrom(addr, 0);

		ProgramLocation loc =
			new OperandFieldLocation(program, addr, null, ref.getToAddress(), "destStr", 0, 0);
		tool.firePluginEvent(new ProgramLocationPluginEvent("test", loc, program));
		cb.updateNow();
		ActionContext context = cb.getProvider().getActionContext(null);

		assertTrue(!setLabel.isEnabledForContext(context));
	}

	@Test
	public void testShowLabelHistory() {
		env.open(program);

		cb.goTo(new LabelFieldLocation(program, program.getAddressFactory().getAddress("0x1002d2b"),
			"AnotherLocal", null, 0));
		ProgramLocation loc = cb.getCurrentLocation();
		assertEquals(0x01002d2b, loc.getAddress().getOffset());
		assertTrue(loc instanceof LabelFieldLocation);

		LabelMgrPlugin labelPlugin = getPlugin(tool, LabelMgrPlugin.class);
		DockingActionIf historyAction = getAction(labelPlugin, "Show Label History");
		performAction(historyAction, cb.getProvider(), false);

		DialogComponentProvider provider = waitForDialogComponent(DialogComponentProvider.class);
		JComponent historyPanel = (JComponent) TestUtils.getInstanceField("workPanel", provider);
		JTable table = (JTable) TestUtils.getInstanceField("historyTable", historyPanel);
		TableModel model = table.getModel();
		Object label = model.getValueAt(0, 1);
		assertEquals(label, "AnotherLocal");

		Object author = model.getValueAt(0, 2);
		assertTrue(author.toString().startsWith(System.getProperty("user.name")));
		close(provider);
	}

	@Test
	public void testNotepadLocations() {
		ActionContext context = new ActionContext();
		assertEquals(false, addLabel.isEnabledForContext(context));

		assertEquals(false, editLabel.isEnabledForContext(context));

		assertEquals(false, removeLabel.isEnabledForContext(context));

		assertEquals(false, setLabel.isEnabledForContext(context));

		env.open(program);
		cb.updateNow();

		context = cb.getProvider().getActionContext(null);
		assertEquals(true, addLabel.isEnabledForContext(context));

		assertEquals(false, editLabel.isEnabledForContext(context));

		assertEquals(false, removeLabel.isEnabledForContext(context));

		assertEquals(false, setLabel.isEnabledForContext(context));

		SampleLocationGenerator locGen = new SampleLocationGenerator(program);
		locGen.toggleOpenComposites(cb);
		locGen.generateLocations(this);

	}

	/**
	 * @see ghidra.app.LocationCallback#locationGenerated(ghidra.program.singleuser.util.ProgramLocation)
	 */
	@Override
	public void locationGenerated(ProgramLocation loc) {

		tool.firePluginEvent(new ProgramLocationPluginEvent("test", loc, program));
		cb.updateNow();
		String caseName = "No Location";
		if (loc != null) {
			caseName = loc.toString();
		}

		int[] componentPath = loc.getComponentPath();
		boolean hasComponentPath = componentPath != null && componentPath.length != 0;

		ActionContext context = cb.getProvider().getActionContext(null);

		assertTrue(context instanceof ListingActionContext);

		if (loc instanceof LabelFieldLocation) {
			Symbol s = labelMgrPlugin.getSymbol((ListingActionContext) context);
			assertEquals(caseName, false, addLabel.isEnabledForContext(context));
			assertEquals(caseName, true, editLabel.isEnabledForContext(context));
			assertEquals(caseName, false, editExternalLocation.isEnabledForContext(context));
			assertEquals(caseName, !s.isDynamic(), removeLabel.isEnabledForContext(context));
			assertEquals(caseName, false, setLabel.isEnabledForContext(context));

			assertEquals(EditLabelAction.EDIT_LABEL,
				editLabel.getPopupMenuData().getMenuItemName());

			return;
		}
		else if (loc instanceof OperandFieldLocation) {
			OperandFieldLocation opLoc = (OperandFieldLocation) loc;
			int opIndex = opLoc.getOperandIndex();

			ReferenceManager refMgr = program.getReferenceManager();
			SymbolTable st = program.getSymbolTable();

			Symbol s = null;
			DataTypeComponent component = null;
			if (hasComponentPath) {
				component = LabelMgrPlugin.getComponent((ListingActionContext) context);
			}
			else {
				Reference ref = refMgr.getPrimaryReferenceFrom(loc.getAddress(), opIndex);
				if (ref != null) {
					s = st.getSymbol(ref);
				}
			}

			assertEquals(caseName, s == null && !hasComponentPath,
				addLabel.isEnabledForContext(context));
			boolean editLabelEnabled =
				((s instanceof CodeSymbol || s instanceof FunctionSymbol) && !s.isExternal()) ||
					component != null;
			assertEquals(caseName, editLabelEnabled, editLabel.isEnabledForContext(context));
			assertEquals(caseName,
				(s instanceof CodeSymbol || s instanceof FunctionSymbol) && s.isExternal(),
				editExternalLocation.isEnabledForContext(context));
			assertEquals(caseName, (s instanceof CodeSymbol && !s.isDynamic() && !s.isExternal()),
				removeLabel.isEnabledForContext(context));
			assertEquals(caseName, s != null && !s.isExternal(),
				setLabel.isEnabledForContext(context));
			if (editLabelEnabled) {
				if (component == null) {
					assertEquals(EditLabelAction.EDIT_LABEL,
						editLabel.getPopupMenuData().getMenuItemName());
				}
				else {
					assertEquals(EditLabelAction.EDIT_FIELDNAME,
						editLabel.getPopupMenuData().getMenuItemName());
				}
			}
			return;
		}

		if (loc instanceof CodeUnitLocation) {

			DataTypeComponent component = null;
			if (hasComponentPath) {
				component = LabelMgrPlugin.getComponent((ListingActionContext) context);
			}

			assertEquals(caseName, !hasComponentPath, addLabel.isEnabledForContext(context));
			assertEquals(caseName, component != null, editLabel.isEnabledForContext(context));
			assertEquals(caseName, false, removeLabel.isEnabledForContext(context));
			assertEquals(caseName, false, setLabel.isEnabledForContext(context));

			if (component != null) {
				assertEquals(EditLabelAction.EDIT_FIELDNAME,
					editLabel.getPopupMenuData().getMenuItemName());
			}
		}
		else if (!(loc instanceof FunctionLocation)) {
			assertEquals(caseName, true, addLabel.isEnabledForContext(context));
			assertEquals(caseName, false, editLabel.isEnabledForContext(context));
			assertEquals(caseName, false, removeLabel.isEnabledForContext(context));
			assertEquals(caseName, false, setLabel.isEnabledForContext(context));
		}
		else {
			assertEquals(caseName, false, addLabel.isEnabledForContext(context));
			assertEquals(caseName, false, editLabel.isEnabledForContext(context));
			assertEquals(caseName, false, removeLabel.isEnabledForContext(context));
			assertEquals(caseName, false, setLabel.isEnabledForContext(context));
		}
	}
}
