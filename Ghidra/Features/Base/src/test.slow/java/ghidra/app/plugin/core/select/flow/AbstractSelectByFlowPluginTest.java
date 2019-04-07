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
package ghidra.app.plugin.core.select.flow;

import org.junit.After;
import org.junit.Before;

import docking.ActionContext;
import docking.action.DockingAction;
import ghidra.GhidraOptions;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.gotoquery.GoToServicePlugin;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.util.ProgramSelection;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.DataConverter;

public abstract class AbstractSelectByFlowPluginTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	CodeBrowserPlugin codeBrowserPlugin;
	PluginTool tool;
	ProgramDB program;
	DataConverter dataConverter;
	SelectByFlowPlugin selectByFlowPlugin;
	ProgramBuilder builder;

	DockingAction selectAllFlowsFromAction;
	DockingAction selectLimitedFlowsFromAction;
	DockingAction selectAllFlowsToAction;
	DockingAction selectLimitedFlowsToAction;

	GoToService goToService;
	AddressFactory addressFactory;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();

		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(SelectByFlowPlugin.class.getName());

		selectByFlowPlugin = env.getPlugin(SelectByFlowPlugin.class);

		selectAllFlowsFromAction =
			(DockingAction) getInstanceField("selectAllFlowsFromAction", selectByFlowPlugin);
		selectLimitedFlowsFromAction =
			(DockingAction) getInstanceField("selectLimitedFlowsFromAction", selectByFlowPlugin);
		selectAllFlowsToAction =
			(DockingAction) getInstanceField("selectAllFlowsToAction", selectByFlowPlugin);
		selectLimitedFlowsToAction =
			(DockingAction) getInstanceField("selectLimitedFlowsToAction", selectByFlowPlugin);

		GoToServicePlugin goToPlugin = env.getPlugin(GoToServicePlugin.class);
		goToService = (GoToService) invokeInstanceMethod("getGotoService", goToPlugin);
		codeBrowserPlugin = env.getPlugin(CodeBrowserPlugin.class);

		env.showTool();

		builder = new FollowFlowProgramBuilder();
		program = builder.getProgram();
		addressFactory = program.getAddressFactory();

		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
	}

	@After
	public void tearDown() throws Exception {

		env.dispose();
	}

	ActionContext getActionContext() {
		CodeViewerProvider provider = codeBrowserPlugin.getProvider();
		return runSwing(() -> provider.getActionContext(null));
	}

	@SuppressWarnings("unused")
	private void defaultFollowFlow(Options options) {
		options.setBoolean(GhidraOptions.OPTION_FOLLOW_COMPUTED_CALL, false);
		options.setBoolean(GhidraOptions.OPTION_FOLLOW_CONDITIONAL_CALL, false);
		options.setBoolean(GhidraOptions.OPTION_FOLLOW_UNCONDITIONAL_CALL, false);
		options.setBoolean(GhidraOptions.OPTION_FOLLOW_COMPUTED_JUMP, false);
		options.setBoolean(GhidraOptions.OPTION_FOLLOW_CONDITIONAL_JUMP, true);
		options.setBoolean(GhidraOptions.OPTION_FOLLOW_UNCONDITIONAL_JUMP, true);
		options.setBoolean(GhidraOptions.OPTION_FOLLOW_POINTERS, false);
	}

	void turnOffAllFollowFlow(Options options) {
		options.setBoolean(GhidraOptions.OPTION_FOLLOW_COMPUTED_CALL, false);
		options.setBoolean(GhidraOptions.OPTION_FOLLOW_CONDITIONAL_CALL, false);
		options.setBoolean(GhidraOptions.OPTION_FOLLOW_UNCONDITIONAL_CALL, false);
		options.setBoolean(GhidraOptions.OPTION_FOLLOW_COMPUTED_JUMP, false);
		options.setBoolean(GhidraOptions.OPTION_FOLLOW_CONDITIONAL_JUMP, false);
		options.setBoolean(GhidraOptions.OPTION_FOLLOW_UNCONDITIONAL_JUMP, false);
		options.setBoolean(GhidraOptions.OPTION_FOLLOW_POINTERS, false);
	}

	void turnOnAllFollowFlow(Options options) {
		options.setBoolean(GhidraOptions.OPTION_FOLLOW_COMPUTED_CALL, true);
		options.setBoolean(GhidraOptions.OPTION_FOLLOW_CONDITIONAL_CALL, true);
		options.setBoolean(GhidraOptions.OPTION_FOLLOW_UNCONDITIONAL_CALL, true);
		options.setBoolean(GhidraOptions.OPTION_FOLLOW_COMPUTED_JUMP, true);
		options.setBoolean(GhidraOptions.OPTION_FOLLOW_CONDITIONAL_JUMP, true);
		options.setBoolean(GhidraOptions.OPTION_FOLLOW_UNCONDITIONAL_JUMP, true);
		options.setBoolean(GhidraOptions.OPTION_FOLLOW_POINTERS, true);
	}

	void followComputedCalls(boolean follow, Options options) {
		options.setBoolean(GhidraOptions.OPTION_FOLLOW_COMPUTED_CALL, follow);
	}

	void followConditionalCalls(boolean follow, Options options) {
		options.setBoolean(GhidraOptions.OPTION_FOLLOW_CONDITIONAL_CALL, follow);
	}

	void followUnconditionalCalls(boolean follow, Options options) {
		options.setBoolean(GhidraOptions.OPTION_FOLLOW_UNCONDITIONAL_CALL, follow);
	}

	void followComputedJumps(boolean follow, Options options) {
		options.setBoolean(GhidraOptions.OPTION_FOLLOW_COMPUTED_JUMP, follow);
	}

	void followConditionalJumps(boolean follow, Options options) {
		options.setBoolean(GhidraOptions.OPTION_FOLLOW_CONDITIONAL_JUMP, follow);
	}

	void followUnconditionalJumps(boolean follow, Options options) {
		options.setBoolean(GhidraOptions.OPTION_FOLLOW_UNCONDITIONAL_JUMP, follow);
	}

	void followPointers(boolean follow, Options options) {
		options.setBoolean(GhidraOptions.OPTION_FOLLOW_POINTERS, follow);
	}

	Address addr(int addr) {
		return builder.addr("0x" + Integer.toHexString(addr));
	}

	void goTo(final Address address) {
		runSwing(() -> goToService.goTo(address));
	}

	void setSelection(AddressSet selectionSet) {
		ProgramSelection selection = new ProgramSelection(selectionSet);
		tool.firePluginEvent(new ProgramSelectionPluginEvent("test", selection, program));
	}

	class MySelection extends ProgramSelection {

		MySelection(ProgramSelection selection) {
			super(selection);
		}

		MySelection(AddressSet addressSet) {
			super(addressSet);
		}

		@Override
		public String toString() {
			StringBuffer buf = new StringBuffer();
			AddressRangeIterator ranges = getAddressRanges();
			for (AddressRange addressRange : ranges) {
				buf.append("\n[" + addressRange.getMinAddress() + " - " +
					addressRange.getMaxAddress() + "]");
			}
			return buf.toString();
		}
	}
}
