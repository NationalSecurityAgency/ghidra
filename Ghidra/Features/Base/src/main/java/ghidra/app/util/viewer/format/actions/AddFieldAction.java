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
package ghidra.app.util.viewer.format.actions;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.util.HelpTopics;
import ghidra.app.util.viewer.field.FieldFactory;
import ghidra.app.util.viewer.format.*;
import ghidra.util.HelpLocation;

/**
 * The action for adding a Field to the current format.
 */
public class AddFieldAction extends DockingAction {
	private FieldHeader panel;
	private final FieldFormatModel formatModel;
	private final FieldFactory myFieldFactory;

	public AddFieldAction(String owner, FieldFactory fieldFactory, FieldHeader panel,
			FieldFormatModel formatModel) {
		super(fieldFactory.getFieldName(), owner, false);
		this.myFieldFactory = fieldFactory;
		this.formatModel = formatModel;
		this.panel = panel;

		setPopupMenuData(
			new MenuData(new String[] { "Add Field", fieldFactory.getFieldName() }, "header b"));
		setEnabled(true);
		setHelpLocation(new HelpLocation(HelpTopics.CODE_BROWSER, "Add Field"));
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context.getContextObject() instanceof FieldHeaderLocation)) {
			return false;
		}

		FieldFactory[] unusedFactories = formatModel.getUnusedFactories();
		for (FieldFactory unusedFieldFactory : unusedFactories) {
			if (unusedFieldFactory == myFieldFactory) {
				return true;
			}
		}
		return false;
	}

	@Override
	public boolean isValidContext(ActionContext context) {
		if (!(context.getContextObject() instanceof FieldHeaderLocation)) {
			return false;
		}

		FieldHeaderLocation loc = (FieldHeaderLocation) context.getContextObject();
		FieldFormatModel modelAtLocation = loc.getModel();
		return (modelAtLocation == formatModel);
	}

	/**
	 * Method called when the action is invoked.
	 */
	@Override
	public void actionPerformed(ActionContext context) {
		FieldHeaderLocation loc = (FieldHeaderLocation) context.getContextObject();
		panel.setTabLock(true);
		formatModel.addFactory(myFieldFactory, loc.getRow(), loc.getColumn());
	}

	@Override
	public String toString() {
		//@formatter:off
		return "{\n" +
			"\tfield: " + myFieldFactory.getFieldName() + "\n" +
			"\tmodel: " + formatModel.getName() + "\n" +
			"\towner: " + getOwner() + "\n" +
		"}";
		//@formatter:on
	}
}
