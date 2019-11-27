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
package ghidra.app.actions;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.DockingUtils;
import docking.action.*;
import ghidra.app.plugin.core.navigation.FindAppliedDataTypesService;
import ghidra.app.plugin.core.navigation.locationreferences.ReferenceUtils;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.util.*;

public abstract class AbstractFindReferencesDataTypeAction extends DockingAction {

	private static final String HELP_TOPIC = HelpTopics.FIND_REFERENCES;
	public static final String NAME = "Find References To";
	public static final KeyStroke DEFAULT_KEY_STROKE = KeyStroke.getKeyStroke(KeyEvent.VK_F,
		DockingUtils.CONTROL_KEY_MODIFIER_MASK | InputEvent.SHIFT_DOWN_MASK);
	private PluginTool tool;

	protected AbstractFindReferencesDataTypeAction(PluginTool tool, String name, String owner) {
		this(tool, name, owner, null);
	}

	protected AbstractFindReferencesDataTypeAction(PluginTool tool, String name, String owner,
			KeyStroke defaultKeyStroke) {
		super(name, owner, KeyBindingType.SHARED);
		this.tool = tool;

		setHelpLocation(new HelpLocation(HELP_TOPIC, "Data_Types"));
		setDescription("Shows all uses of the selected data type");

		initKeyStroke(defaultKeyStroke);
	}

	protected abstract DataType getDataType(ActionContext context);

	protected String getDataTypeField() {
		// The base implementation only searches for references to the data type, not specific
		// fields.  Subclasses can change this behavior
		return null;
	}

	private void initKeyStroke(KeyStroke keyStroke) {
		if (keyStroke == null) {
			return;
		}

		setKeyBindingData(new KeyBindingData(keyStroke));
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		DataType dataType = getDataType(context);
		return dataType != null;
	}

	@Override
	public void actionPerformed(ActionContext context) {

		FindAppliedDataTypesService service = tool.getService(FindAppliedDataTypesService.class);
		if (service == null) {
			Msg.showError(this, null, "Missing Plugin",
				"The FindAppliedDataTypesService is not installed.\n" +
					"Please add the plugin implementing this service.");
			return;
		}

		DataType dataType = getDataType(context);
		DataType baseDataType = ReferenceUtils.getBaseDataType(dataType);
		String field = getDataTypeField();

		// sanity check - should not happen
		if (field != null && !(baseDataType instanceof Composite)) {
			Msg.error(this, "Somehow have a field without a Composite parent--searching " +
				"only for the parent type '" + dataType + "'; field '" + field + "'");
			Swing.runLater(() -> service.findAndDisplayAppliedDataTypeAddresses(dataType));
			return;
		}

		if (field == null) {
			Swing.runLater(() -> service.findAndDisplayAppliedDataTypeAddresses(dataType));
		}
		else {
			Swing.runLater(() -> service.findAndDisplayAppliedDataTypeAddresses(
				(Composite) baseDataType, field));
		}
	}

}
