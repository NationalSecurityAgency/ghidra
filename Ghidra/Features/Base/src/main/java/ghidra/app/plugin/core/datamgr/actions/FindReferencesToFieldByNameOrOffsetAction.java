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
package ghidra.app.plugin.core.datamgr.actions;

import java.util.ArrayList;
import java.util.List;

import javax.swing.tree.TreePath;

import org.apache.commons.lang3.StringUtils;

import docking.ActionContext;
import docking.widgets.OptionDialog;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.tree.DataTypeNode;
import ghidra.app.services.FieldMatcher;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.util.NumericUtilities;

/**
 * An action that can be used on a {@link Composite} or {@link Enum} to find references to a field
 * by name or offset.
 */
public class FindReferencesToFieldByNameOrOffsetAction extends AbstractFindReferencesToFieldAction {

	public FindReferencesToFieldByNameOrOffsetAction(Plugin plugin) {
		super(plugin);
	}

	@Override
	protected DataTypeAndFields getSelectedType(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return null;
		}

		Object contextObject = context.getContextObject();
		GTree gtree = (GTree) contextObject;
		TreePath[] selectionPaths = gtree.getSelectionPaths();
		if (selectionPaths.length != 1) {
			return null;
		}

		GTreeNode node = (GTreeNode) selectionPaths[0].getLastPathComponent();
		if (!(node instanceof DataTypeNode)) {
			return null;
		}
		DataTypeNode dtNode = (DataTypeNode) node;
		DataType dt = dtNode.getDataType();
		if (!(dt instanceof Composite || dt instanceof Enum)) {
			return null;
		}

		String[] fields = null;
		if (dt instanceof Composite) {
			fields = getCompositeFieldNames((Composite) dt);
		}
		else if (dt instanceof Enum) {
			fields = ((Enum) dt).getNames();
		}

		return new DataTypeAndFields(dt, fields);
	}

	@Override
	protected FieldMatcher createFieldMatcher(DataTypeAndFields typeAndFields) {

		DataType dt = typeAndFields.dataType();
		String message = "Find uses of '" + dt.getName() + "' field by name or offset";
		String userChoice = OptionDialog.showEditableInputChoiceDialog(null, "Choose Field",
			message, typeAndFields.fieldNames(), null, OptionDialog.QUESTION_MESSAGE);
		if (userChoice == null) {
			return null; // cancelled
		}

		Long longChoice = parseInt(userChoice);
		if (longChoice != null) {
			return new FieldMatcher(dt, longChoice.intValue());
		}
		return new FieldMatcher(dt, userChoice);
	}

	private String[] getCompositeFieldNames(Composite composite) {
		DataTypeComponent[] components = composite.getDefinedComponents();
		List<String> names = new ArrayList<>();
		for (DataTypeComponent dataTypeComponent : components) {
			if (dataTypeComponent.isBitFieldComponent()) {
				continue;
			}
			String fieldName = dataTypeComponent.getFieldName();
			if (StringUtils.isBlank(fieldName)) {
				continue;
			}
			names.add(fieldName);
		}

		return names.toArray(String[]::new);
	}

	private Long parseInt(String s) {
		return NumericUtilities.parseNumber(s, null);
	}
}
