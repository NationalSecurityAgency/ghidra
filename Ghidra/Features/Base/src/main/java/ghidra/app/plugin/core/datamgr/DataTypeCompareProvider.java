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
package ghidra.app.plugin.core.datamgr;

import java.awt.Component;
import java.awt.event.MouseEvent;

import javax.swing.JComponent;

import docking.*;
import docking.action.builder.ActionBuilder;
import ghidra.app.services.DataTypeManagerService;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.util.HelpLocation;
import resources.Icons;

/**
 * A provider that shows a comparison between two data types.
 */
public class DataTypeCompareProvider extends ComponentProvider {

	private DataTypeComparePanel compareComponent;
	private DataType rightDt;
	private DataType leftDt;

	public DataTypeCompareProvider(Tool tool, String owner, DataType leftDt, DataType rightDt) {
		super(tool, "Data Type Compare", owner);
		this.leftDt = leftDt;
		this.rightDt = rightDt;

		setTransient();
		setSubTitle(leftDt.getName() + " / " + rightDt.getName());
		setTabText(leftDt.getName());
		setWindowMenuGroup(getName());
		setHelpLocation(new HelpLocation(owner, "Compare"));

		build();

		createActions();

		addToTool();
	}

	private void createActions() {

		new ActionBuilder("Show Data Type", getOwner())
				.popupMenuPath("Show Data Type")
				.onAction(this::showType)
				.buildAndInstallLocal(this);

		new ActionBuilder("Refresh", getOwner())
				.toolBarIcon(Icons.REFRESH_ICON)
				.onAction(this::refresh)
				.buildAndInstallLocal(this);
	}

	private void showType(ActionContext context) {

		MouseEvent event = context.getMouseEvent();
		Component mouseComponent = event.getComponent();
		boolean isLeft = compareComponent.isLeft(mouseComponent);
		DataType dt = isLeft ? leftDt : rightDt;

		DataTypeManagerService service =
			getTool().getService(DataTypeManagerService.class);
		service.setDataTypeSelected(dt);
	}

	private void refresh(ActionContext context) {
		DataTypeManager leftDtm = leftDt.getDataTypeManager();
		DataTypeManager rightDtm = rightDt.getDataTypeManager();
		leftDt = leftDtm.resolve(leftDt, null);
		rightDt = rightDtm.resolve(rightDt, null);

		compareComponent.setDataTypes(leftDt, rightDt);
	}

	private void build() {
		DataTypeManager leftDtm = leftDt.getDataTypeManager();
		DataTypeManager rightDtm = rightDt.getDataTypeManager();

		String leftName = leftDtm.getName();
		String rightName = rightDtm.getName();
		compareComponent = new DataTypeComparePanel(leftName, rightName);
		compareComponent.setDataTypes(leftDt, rightDt);
	}

	@Override
	public JComponent getComponent() {
		return compareComponent;
	}

}
