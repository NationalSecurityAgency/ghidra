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
package ghidra.app.plugin.core.validator;

import java.lang.reflect.Constructor;
import java.util.*;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import docking.widgets.conditiontestpanel.ConditionTester;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.analysis.validator.PostAnalysisValidator;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;

/**
 * Display a pop-up dialog to run PostAnalysisValidator tests on the Program
 * that is currently open in the tool.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Validates program analysis",
	description = "This plugin provides an action that displays a dialog to run post-analysis validation tests on a program"
)
//@formatter:on
public class ValidateProgramPlugin extends Plugin {
	public final static String PLUGIN_NAME = "ValidateProgramPlugin";
	public final static String ACTION_NAME = "Validate Program";

	private DockingAction validateAction;

	public ValidateProgramPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		setupActions();
	}

	@Override
	public void dispose() {
		tool.removeAction(validateAction);
		validateAction.dispose();
		super.dispose();
	}

	private void setupActions() {
		validateAction = new ProgramContextAction(ACTION_NAME, PLUGIN_NAME) {
			@Override
			public void actionPerformed(ProgramActionContext context) {
				Program program = context.getProgram();
				validate(program);
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (!super.isEnabledForContext(context)) {
					getMenuBarData().setMenuItemName(ACTION_NAME);
					return false;
				}
				return true;
			}

			@Override
			public boolean isEnabledForContext(ProgramActionContext context) {
				Program program = context.getProgram();
				String menuName = "Validate " + program.getDomainFile().getName();
				getMenuBarData().setMenuItemName(menuName);
				return true;
			}
		};
		validateAction.addToWindowWhen(ListingActionContext.class);
		validateAction.setMenuBarData(new MenuData(new String[] { ToolConstants.MENU_ANALYSIS,
			ACTION_NAME }, null, "ZZZ"));

		validateAction.setEnabled(false);

		validateAction.setHelpLocation(new HelpLocation("ValidateProgram", "top_of_page"));
		validateAction.setDescription(getPluginDescription().getDescription());
		tool.addAction(validateAction);
	}

	private void validate(Program program) {
		List<ConditionTester> list = getConditionTests(program);
		Collections.sort(list, new ConditionsComparator());
		ValidateProgramDialog dialog = new ValidateProgramDialog(program, list);
		tool.showDialog(dialog);
	}

	private List<ConditionTester> getConditionTests(Program program) {
		List<ConditionTester> list = new ArrayList<ConditionTester>();

		List<Class<? extends PostAnalysisValidator>> validatorClasses =
			ClassSearcher.getClasses(PostAnalysisValidator.class);
		for (Class<? extends PostAnalysisValidator> validatorClass : validatorClasses) {
			try {
				Constructor<? extends PostAnalysisValidator> ctor =
					validatorClass.getConstructor(Program.class);
				PostAnalysisValidator validator = ctor.newInstance(program);
				list.add(validator);
			}
			catch (Exception e) {
				Msg.error(this, "error including PostAnalysisValidator " + validatorClass, e);
			}
		}
		return list;
	}

	private class ConditionsComparator implements Comparator<ConditionTester> {
		@Override
		public int compare(ConditionTester o1, ConditionTester o2) {
			return o1.getName().compareTo(o2.getName());
		}
	}
}
