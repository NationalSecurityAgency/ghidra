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
package ghidra.app.plugin.core.fallthrough;

import static org.junit.Assert.assertEquals;

import java.util.Set;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import ghidra.app.LocationCallback;
import ghidra.app.SampleLocationGenerator;
import ghidra.app.context.ListingActionContext;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.test.*;

public class FallThroughActionTest extends AbstractGhidraHeadedIntegrationTest
		implements LocationCallback {
	private Program program;
	private TestEnv env;
	private PluginTool tool;
	private Plugin plugin;
	private CodeBrowserPlugin cb;
	private static final String AUTO_OVERRIDE = "Auto Set Fallthroughs";
	private static final String CLEAR_FALLTHROUGH = "Clear Fallthroughs";

	public FallThroughActionTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(FallThroughPlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		plugin = getPlugin(tool, FallThroughPlugin.class);
		cb = getPlugin(tool, CodeBrowserPlugin.class);

		ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder();
		program = builder.getProgram();
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	@Test
	public void testNotepadLocations() {
		Set<DockingActionIf> actions = getActionsByOwner(tool, plugin.getName());
		checkAction(actions, AUTO_OVERRIDE, false, "Start");
		checkAction(actions, CLEAR_FALLTHROUGH, false, "Start");

		env.open(program);
		checkAction(actions, AUTO_OVERRIDE, false, "Open");
		checkAction(actions, CLEAR_FALLTHROUGH, false, "Open");

		SampleLocationGenerator locGen = new SampleLocationGenerator(program);
		locGen.generateLocations(this);

		env.close(program);
		checkAction(actions, AUTO_OVERRIDE, false, "Close");
		checkAction(actions, CLEAR_FALLTHROUGH, false, "Close");
	}

	@Test
	public void testNotepadSelections() {
		env.open(program);

		ProgramSelection selection =
			new ProgramSelection(program.getMinAddress(), program.getMaxAddress());
		ProgramSelectionPluginEvent ev =
			new ProgramSelectionPluginEvent("Test", selection, program);
		tool.firePluginEvent(ev);

		Set<DockingActionIf> actions = getActionsByOwner(tool, plugin.getName());
		checkAction(actions, AUTO_OVERRIDE, true, "selection");
		checkAction(actions, CLEAR_FALLTHROUGH, true, "selection");

		selection = new ProgramSelection();
		ev = new ProgramSelectionPluginEvent("Test", selection, program);
		tool.firePluginEvent(ev);
		checkAction(actions, AUTO_OVERRIDE, false, "selection");
		checkAction(actions, CLEAR_FALLTHROUGH, false, "selection");
	}

	@Override
	public void locationGenerated(ProgramLocation loc) {
		tool.firePluginEvent(new ProgramLocationPluginEvent("test", loc, program));
		Set<DockingActionIf> actions = getActionsByOwner(tool, plugin.getName());

		ListingActionContext actionContext =
			(ListingActionContext) cb.getProvider().getActionContext(null);
		Instruction inst = program.getListing().getInstructionAt(actionContext.getAddress());
		if (inst == null) {
			checkAction(actions, AUTO_OVERRIDE, false, loc.toString());
			checkAction(actions, CLEAR_FALLTHROUGH, false, loc.toString());
		}
		else {
			checkAction(actions, AUTO_OVERRIDE, true, loc.toString());
			checkAction(actions, CLEAR_FALLTHROUGH, inst.isFallThroughOverridden(), loc.toString());
		}

	}

	private void checkAction(Set<DockingActionIf> actions, String name, boolean isValidContext,
			String caseName) {
		for (DockingActionIf action : actions) {
			String actionName = action.getName();
			int pos = actionName.indexOf(" (");
			if (pos > 0) {
				actionName = actionName.substring(0, pos);
			}
			if (actionName.equals(name)) {
				ActionContext actionContext = cb.getProvider().getActionContext(null);
				if (actionContext == null) {
					actionContext = new ActionContext();
				}
				boolean validContext = action.isAddToPopup(actionContext);
				assertEquals("Enablement: actionName = " + actionName + " [case: " + caseName + "]",
					isValidContext, validContext);
				return;
			}
		}
		Assert.fail("Action " + name + " not found");
	}

}
