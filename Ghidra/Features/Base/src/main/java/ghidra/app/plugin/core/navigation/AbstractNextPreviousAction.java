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
package ghidra.app.plugin.core.navigation;

import java.awt.event.ActionEvent;

import javax.swing.Icon;
import javax.swing.KeyStroke;

import docking.action.KeyBindingData;
import docking.action.ToolBarData;
import docking.tool.ToolConstants;
import generic.util.image.ImageUtils;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.context.NavigatableContextAction;
import ghidra.app.nav.Navigatable;
import ghidra.app.services.GoToService;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.AddressFieldLocation;
import ghidra.util.HelpLocation;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;
import resources.*;

public abstract class AbstractNextPreviousAction extends NavigatableContextAction {

	private static final Icon INVERTED_OVERLAY_ICON =
		ImageUtils.makeTransparent(Icons.NOT_ALLOWED_ICON, .5f);

	private boolean isForward = true;
	private PluginTool tool;

	protected boolean isInverted;
	private Icon invertedIcon;

	public AbstractNextPreviousAction(PluginTool tool, String name, String owner, String subGroup) {
		super(name, owner);
		this.tool = tool;
		ToolBarData toolBarData =
			new ToolBarData(getIcon(), ToolConstants.TOOLBAR_GROUP_FOUR);
		toolBarData.setToolBarSubGroup(subGroup);
		setToolBarData(toolBarData);
		setKeyBindingData(new KeyBindingData(getKeyStroke()));
		setHelpLocation(new HelpLocation(HelpTopics.NAVIGATION, name));
		setDescription(getDescriptionString());
		addToWindowWhen(NavigatableActionContext.class);

		MultiIconBuilder builder = new MultiIconBuilder(getIcon());
		builder.addIcon(INVERTED_OVERLAY_ICON, 10, 10, QUADRANT.LR);
		invertedIcon = builder.build();
	}

	protected void setInverted(boolean isInverted) {
		this.isInverted = isInverted;
		getToolBarData().setIcon(isInverted ? invertedIcon : getIcon());
		setDescription(getDescriptionString());
	}

	protected abstract Icon getIcon();

	protected abstract KeyStroke getKeyStroke();

	@Override
	public void actionPerformed(final NavigatableActionContext context) {
		Task t = new Task("Searching for " + doGetNavigationTypeName(), true, false, true) {
			@Override
			public void run(TaskMonitor monitor) {
				gotoNextPrevious(monitor, context);
			}
		};
		new TaskLauncher(t);
	}

	void gotoNextPrevious(TaskMonitor monitor, final NavigatableActionContext context) {

		try {
			boolean direction = isForward;
			if (context.hasAnyEventClickModifiers(ActionEvent.SHIFT_MASK)) {
				direction = !direction;
			}

			Address address = direction
					? getNextAddress(monitor, context.getProgram(), context.getAddress())
					: getPreviousAddress(monitor, context.getProgram(), context.getAddress());

			Swing.runLater(() -> gotoAddress(context, address));
		}
		catch (CancelledException e) {
			// cancelled
		}
	}

	private void gotoAddress(NavigatableActionContext actionContext, Address address) {
		if (address == null) {
			tool.setStatusInfo("Unable to locate another \"" + doGetNavigationTypeName() +
				"\" past the current range, in the current direction.");
			return;
		}
		tool.clearStatusInfo();

		GoToService service = tool.getService(GoToService.class);
		if (service != null) {
			Navigatable navigatable = actionContext.getNavigatable();
			gotoAddress(service, navigatable, address);
		}

	}

	protected void gotoAddress(GoToService service, Navigatable navigatable, Address address) {
		Program program = navigatable.getProgram();
		service.goTo(navigatable, new AddressFieldLocation(program, address), program);
	}

	void setDirection(boolean isForward) {
		this.isForward = isForward;
		setDescription(getDescriptionString());
	}

	private String getDescriptionString() {
		String prefix = isForward ? "Go To Next " : "Go To Previous ";
		return prefix + doGetNavigationTypeName() + " (shift-click inverts direction)";
	}

	private String doGetNavigationTypeName() {
		if (isInverted) {
			return getInvertedNavigationTypeName();
		}
		return getNavigationTypeName();
	}

	abstract protected String getNavigationTypeName();

	protected String getInvertedNavigationTypeName() {
		return "Non-" + getNavigationTypeName();
	}

	abstract protected Address getNextAddress(TaskMonitor monitor, Program program, Address address)
			throws CancelledException;

	abstract protected Address getPreviousAddress(TaskMonitor monitor, Program program,
			Address address) throws CancelledException;

}
