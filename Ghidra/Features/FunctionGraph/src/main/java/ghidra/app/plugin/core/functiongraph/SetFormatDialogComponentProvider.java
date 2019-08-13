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
package ghidra.app.plugin.core.functiongraph;

import java.awt.BorderLayout;
import java.awt.event.MouseEvent;
import java.util.List;

import javax.swing.JComponent;
import javax.swing.JPanel;

import org.jdom.Element;

import docking.ActionContext;
import docking.DialogComponentProvider;
import docking.action.*;
import docking.widgets.OptionDialog;
import ghidra.app.util.viewer.format.*;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;

public class SetFormatDialogComponentProvider extends DialogComponentProvider {

	private final FormatManager currentFormatManager;
	private final FormatManager defaultFormatManager;
	private FormatManager newFormatManager;
	private ListingPanel listingPanel;
	private final Program program;
	private final AddressSetView view;

	public SetFormatDialogComponentProvider(FormatManager defaultManager,
			FormatManager currentFormatManager, ServiceProvider serviceProvider, Program program,
			AddressSetView view) {
		super("Edit Code Layout", true, false, true, false);
		this.defaultFormatManager = defaultManager;
		this.currentFormatManager = currentFormatManager;
		this.program = program;
		this.view = view;

		setPreferredSize(600, 500);

		addWorkPanel(createWorkPanel());
		addOKButton();
		addCancelButton();

		List<DockingActionIf> headerActions = listingPanel.getHeaderActions(getTitle());
		for (DockingActionIf action : headerActions) {
			if ("Reset All Formats".equals(action.getName())) {
				continue;
			}
			else if ("Reset Format".equals(action.getName())) {
				continue;
			}
			addAction(action);
		}

		addAction(new CustomResetFormatAction());
		addAction(new CustomResetAllFormatAction());
	}

	private JComponent createWorkPanel() {
		JPanel container = new JPanel(new BorderLayout());
		listingPanel = createListingPanel();
		listingPanel.showHeader(true);

		container.add(listingPanel);

		return container;
	}

	private ListingPanel createListingPanel() {
		FormatManager formatManagerCopy = currentFormatManager.createClone();
		ListingPanel panel = new ListingPanel(formatManagerCopy, program);
		panel.setView(view);
		return panel;
	}

	public FormatManager getNewFormatManager() {
		return newFormatManager;
	}

	@Override
	protected void okCallback() {
		newFormatManager = listingPanel.getFormatManager();
		close();
	}

	@Override
	protected void cancelCallback() {
		newFormatManager = null;
		super.cancelCallback();
	}

	@Override
	public void close() {
		super.close();
		listingPanel.dispose();
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (event == null) {
			return null;
		}

		FieldHeader headerPanel = listingPanel.getFieldHeader();
		if (headerPanel != null && headerPanel.isAncestorOf(event.getComponent())) {
			FieldHeaderLocation fhLoc = headerPanel.getFieldHeaderLocation(event.getPoint());
			return new ActionContext().setContextObject(fhLoc);
		}
		return null;
	}

	/*testing*/ FieldHeader getFieldHeader() {
		return listingPanel.getFieldHeader();
	}
//==================================================================================================
// Inner Classes
//==================================================================================================

	private class CustomResetAllFormatAction extends DockingAction {

		public CustomResetAllFormatAction() {
			super("Reset All Formats", getTitle(), false);

			setPopupMenuData(new MenuData(new String[] { "Reset All Formats" }, null, "format"));
			setEnabled(true);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			return context.getContextObject() instanceof FieldHeaderLocation;
		}

		@Override
		public void actionPerformed(ActionContext context) {
			int userChoice = OptionDialog.showOptionDialog(listingPanel, "Reset All Formats?",
				"There is no undo for this action.\n" +
					"Are you sure you want to reset all formats?",
				"Continue", OptionDialog.WARNING_MESSAGE);
			if (userChoice == OptionDialog.CANCEL_OPTION) {
				return;
			}

			FormatManager listingFormatManager = listingPanel.getFormatManager();
			SaveState saveState = new SaveState();
			defaultFormatManager.saveState(saveState);

			// update the dialog's GUI (which will later be used as the new format if the
			// user presses OK)
			listingFormatManager.readState(saveState);
		}
	}

	private class CustomResetFormatAction extends DockingAction {

		public CustomResetFormatAction() {
			super("Reset Format", getTitle(), false);

			setPopupMenuData(new MenuData(new String[] { "Reset Format" }, null, "format"));
			setEnabled(true);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			return context.getContextObject() instanceof FieldHeaderLocation;
		}

		@Override
		public void actionPerformed(ActionContext context) {
			FieldHeader fieldHeader = listingPanel.getFieldHeader();
			int index = fieldHeader.getSelectedIndex();
			FieldFormatModel originalModel = defaultFormatManager.getModel(index);
			Element originalXML = originalModel.saveToXml();

			// update the dialog's GUI (which will later be used as the new format if the
			// user presses OK)
			FormatManager listingFormatManager = listingPanel.getFormatManager();
			FieldFormatModel currentModel = listingFormatManager.getModel(index);
			currentModel.restoreFromXml(originalXML);
		}
	}
}
