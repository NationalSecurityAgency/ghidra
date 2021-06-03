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
package ghidra.app.merge;

import java.awt.*;

import javax.swing.*;

import docking.help.Help;
import docking.help.HelpService;
import generic.util.WindowUtilities;
import ghidra.app.merge.datatypes.DataTypeMergeManager;
import ghidra.app.merge.listing.*;
import ghidra.app.merge.memory.MemoryMergeManager;
import ghidra.app.merge.propertylist.PropertyListMergeManager;
import ghidra.app.merge.tool.ListingMergePanel;
import ghidra.app.merge.tool.ListingMergePanelPlugin;
import ghidra.app.merge.tree.ProgramTreeMergeManager;
import ghidra.app.nav.*;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.util.FieldNavigator;
import ghidra.framework.model.UndoableDomainObject;
import ghidra.framework.plugintool.ModalPluginTool;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramChangeSet;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;

/** 
 * Top level object that manages each step of the merge/resolve conflicts
 * process.
 */
public class ProgramMultiUserMergeManager extends MergeManager {

	private ListingMergePanelPlugin listingPlugin;
	private GoToAddressLabelPlugin goToPlugin;
	private ListingMergePanel mergePanel;
	private boolean isShowingListingMergePanel = false;
	private boolean showListingPanels = true;
	MergeNavigatable navigatable;

	public ProgramMultiUserMergeManager(Program resultProgram, Program myProgram,
			Program originalProgram, Program latestProgram, ProgramChangeSet latestChangeSet,
			ProgramChangeSet myChangeSet) {
		super(resultProgram, myProgram, originalProgram, latestProgram, latestChangeSet,
			myChangeSet);
	}

	public ProgramMultiUserMergeManager(Program resultProgram, Program myProgram,
			Program originalProgram, Program latestProgram, ProgramChangeSet latestChangeSet,
			ProgramChangeSet myChangeSet, boolean showListingPanels) {
		super(resultProgram, myProgram, originalProgram, latestProgram, latestChangeSet,
			myChangeSet);

		// True signals to show the Listing panels (the default); false signals to leave the
		// panels empty.
		this.showListingPanels = showListingPanels;
	}

	@Override
	protected void createMergeResolvers() {
		Program resultProgram = (Program) resultDomainObject;
		Program myProgram = (Program) myDomainObject;
		Program originalProgram = (Program) originalDomainObject;
		Program latestProgram = (Program) latestDomainObject;
		// create the merge resolvers
		int idx = 0;
		mergeResolvers = new MergeResolver[8];
		mergeResolvers[idx++] =
			new MemoryMergeManager(this, resultProgram, myProgram, originalProgram, latestProgram);

		mergeResolvers[idx++] =
			new ProgramTreeMergeManager(this, resultProgram, myProgram, originalProgram,
				latestProgram, (ProgramChangeSet) latestChangeSet, (ProgramChangeSet) myChangeSet);

		mergeResolvers[idx++] =
			new DataTypeMergeManager(this, resultProgram, myProgram, originalProgram, latestProgram,
				(ProgramChangeSet) latestChangeSet, (ProgramChangeSet) myChangeSet);

		mergeResolvers[idx++] =
			new ProgramContextMergeManager(this, resultProgram, originalProgram, latestProgram,
				myProgram, (ProgramChangeSet) latestChangeSet, (ProgramChangeSet) myChangeSet);

		mergeResolvers[idx++] =
			new FunctionTagMerger(this, resultProgram, originalProgram, latestProgram, myProgram,
				(ProgramChangeSet) latestChangeSet, (ProgramChangeSet) myChangeSet);

		ListingMergeManager listingMergeManager =
			new ListingMergeManager(this, resultProgram, originalProgram, latestProgram, myProgram,
				(ProgramChangeSet) latestChangeSet, (ProgramChangeSet) myChangeSet);
		listingMergeManager.setShowListingPanel(showListingPanels);
		mergeResolvers[idx++] = listingMergeManager;

		mergeResolvers[idx++] =
			new ExternalProgramMerger(this, resultProgram, originalProgram, latestProgram,
				myProgram, (ProgramChangeSet) latestChangeSet, (ProgramChangeSet) myChangeSet);

		mergeResolvers[idx++] = new PropertyListMergeManager(this, resultProgram, myProgram,
			originalProgram, latestProgram);
	}

	/**
	 * Returns one of the four programs involved in the merge as indicated by the version.
	 * @param version the program version to return. (LATEST, MY, ORIGINAL, or RESULT).
	 * @return the indicated program version or null if a valid version isn't specified.
	 * @see MergeConstants
	 */
	public Program getProgram(int version) {
		switch (version) {
			case MergeConstants.LATEST:
				return (Program) resultDomainObject;
			case MergeConstants.MY:
				return (Program) myDomainObject;
			case MergeConstants.ORIGINAL:
				return (Program) originalDomainObject;
			case MergeConstants.RESULT:
				return (Program) latestDomainObject;
			default:
				return null;
		}
	}

	@Override
	protected MergeManagerPlugin createMergeManagerPlugin(ModalPluginTool mergePluginTool,
			MergeManager multiUserMergeManager, UndoableDomainObject modifiableDomainObject) {
		return new ProgramMergeManagerPlugin(mergeTool, ProgramMultiUserMergeManager.this,
			(Program) resultDomainObject);
	}

	@Override
	protected void initializeMerge() {
		mergePanel = new ListingMergePanel(mergeTool, (Program) originalDomainObject,
			(Program) resultDomainObject, (Program) myDomainObject, (Program) latestDomainObject,
			showListingPanels);
		mergePanel.removeDomainObjectListener();
		navigatable = new MergeNavigatable(mergePanel);
		mergePanel.addButtonPressedListener(new FieldNavigator(mergeTool, navigatable));

		// Currently this sets the merge panel height and width to be centered and
		// about 100 pixels in from the screen edge. 
		Dimension screenDim = Toolkit.getDefaultToolkit().getScreenSize();
		mergePanel.setPreferredSize(new Dimension(screenDim.width - 200, screenDim.height - 200));
		Dimension d = mergePanel.getPreferredSize();
		mergeTool.setSize(d.width + 20, d.height + 20);
		Point centerLoc = WindowUtilities.centerOnScreen(mergeTool.getSize());
		mergeTool.setLocation(centerLoc.x, centerLoc.y);
	}

	@Override
	protected void cleanupMerge() {
		mergePanel.dispose();
		mergePanel = null;
	}

	/**
	 * Show the default merge panel. The default merge panel now shows the status of each phase
	 * of the merge and also the progress in the current phase.
	 *@param description description of current merge process near the top of the merge tool.
	 */
	@Override
	public void showDefaultMergePanel(final String description) {
		if (isShowingListingMergePanel) {
			removeListingMergePanel();
		}
		showComponent(null, null, null);
		SwingUtilities.invokeLater(() -> mergePlugin.updateMergeDescription(description));
	}

	/**
	 * Show the component that is used to resolve conflicts. This method
	 * is called by the MergeResolvers when user input is required. If the
	 * component is not null, this method blocks until the user either 
	 * cancels the merge process or resolves a conflict. If comp is null,
	 * then the default component is displayed, and the method does not
	 * wait for user input.
	 * @param comp component to show; if component is null, show the 
	 * default component and do not block
	 * @param componentID id or name for the component
	 */
	@Override
	public void showComponent(final JComponent comp, final String componentID,
			HelpLocation helpLoc) {

		HelpService help = Help.getHelpService();
		if (helpLoc != null && comp != null) {
			help.registerHelp(comp, helpLoc);
		}

		SwingUtilities.invokeLater(() -> {
			showMergeTool();
			Dimension oldSize = mergeTool.getSize();
			if (listingPlugin != null) {
				mergeTool.removePlugins(new Plugin[] { listingPlugin, goToPlugin });
				listingPlugin = null;
				goToPlugin = null;
			}
			if (comp == null) {
				mergePlugin.showDefaultComponent();
			}
			else {
				mergePlugin.setMergeComponent(comp, componentID);
			}
			Dimension newSize = mergeTool.getSize();
			if (!newSize.equals(oldSize)) {
				Point centerLoc = WindowUtilities.centerOnScreen(mergeTool.getSize());
				mergeTool.setLocation(centerLoc.x, centerLoc.y);
			}
		});
		if (comp != null) {
			inputReceived = false;
			// block until the user takes action
			waitForInput();
		}
	}

	/**
	 * Show the listing merge panel.
	 * @param goToAddress the address to goto.
	 */
	public void showListingMergePanel(final Address goToAddress) {
		SwingUtilities.invokeLater(() -> {
			showMergeTool();
			if (isShowingListingMergePanel) {
				mergePanel.goTo(goToAddress);
				mergePanel.validate();
				return;
			}

			mergePanel.addDomainObjectListener();
			listingPlugin = new ListingMergePanelPlugin(mergeTool, mergePanel);
			goToPlugin = new GoToAddressLabelPlugin(mergeTool);
			try {
				mergeTool.addPlugin(listingPlugin);
				mergeTool.addPlugin(goToPlugin);
			}
			catch (PluginException e) {
				e.printStackTrace();
			}
			mergePlugin.setMergeComponent(mergePanel, "Listing Merge");
//				Dimension d = mergePanel.getPreferredSize();
//				mergeTool.setSize(d.width+20, d.height+20);
//				Point centerLoc = WindowUtilities.centerOnScreen(mergeTool.getSize());
//				mergeTool.setLocation(centerLoc.x, centerLoc.y);

			mergePanel.goTo(goToAddress);
			isShowingListingMergePanel = true;
		});
		inputReceived = false;

		// block until the user takes action
		waitForInput();
	}

	/**
	 * Show the listing merge panel with each listing positioned to the indicated address.
	 * A null can be passed for any address to indicate that listing should be empty.
	 * @param resultAddress the address for positioning the Result program's listing.
	 * @param latestAddress the address for positioning the Latest program's listing.
	 * @param myAddress the address for positioning the My program's listing.
	 * @param originalAddress the address for positioning the Original program's listing.
	 */
	public void refreshListingMergePanel(final Address resultAddress, final Address latestAddress,
			final Address myAddress, final Address originalAddress) {
		SwingUtilities.invokeLater(() -> {
			ProgramSpecificAddressTranslator translator = new ProgramSpecificAddressTranslator();
			translator.addProgramAddress(getProgram(MergeConstants.RESULT), resultAddress);
			translator.addProgramAddress(getProgram(MergeConstants.LATEST), latestAddress);
			translator.addProgramAddress(getProgram(MergeConstants.MY), myAddress);
			translator.addProgramAddress(getProgram(MergeConstants.ORIGINAL), originalAddress);

			mergePanel.setAddressTranslator(translator);

			mergePanel.goTo(resultAddress, MergeConstants.RESULT);
			mergePanel.goTo(latestAddress, MergeConstants.LATEST);
			mergePanel.goTo(myAddress, MergeConstants.MY);
			mergePanel.goTo(originalAddress, MergeConstants.ORIGINAL);
		});
	}

	/**
	 * Show the listing merge panel with each listing positioned to the indicated address.
	 * A null can be passed for any address to indicate that listing should be empty.
	 * @param resultAddress the address for positioning the Result program's listing.
	 * @param latestAddress the address for positioning the Latest program's listing.
	 * @param myAddress the address for positioning the My program's listing.
	 * @param originalAddress the address for positioning the Original program's listing.
	 */
	public void showListingMergePanel(final Address resultAddress, final Address latestAddress,
			final Address myAddress, final Address originalAddress) {
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				showMergeTool();
				if (!isShowingListingMergePanel) {
					mergePanel.addDomainObjectListener();
					listingPlugin = new ListingMergePanelPlugin(mergeTool, mergePanel);
					goToPlugin = new GoToAddressLabelPlugin(mergeTool);
					try {
						mergeTool.addPlugin(listingPlugin);
						mergeTool.addPlugin(goToPlugin);
					}
					catch (PluginException e) {
						e.printStackTrace();
					}
					mergePlugin.setMergeComponent(mergePanel, "Listing Merge");

					// unlock the individual listing panels so they can move/display independent addresses.
					// TODO

//					Dimension d = mergePanel.getPreferredSize();
//					mergeTool.setSize(d.width+20, d.height+20);
//					Point centerLoc = WindowUtilities.centerOnScreen(mergeTool.getSize());
//					mergeTool.setLocation(centerLoc.x, centerLoc.y);
				}

				loadExternalsIntoMergePanel(resultAddress, latestAddress, myAddress,
					originalAddress);

				isShowingListingMergePanel = true;
			}

			private void loadExternalsIntoMergePanel(final Address resultAddress,
					final Address latestAddress, final Address myAddress,
					final Address originalAddress) {

				ProgramSpecificAddressTranslator translator =
					new ProgramSpecificAddressTranslator();
				translator.addProgramAddress(getProgram(MergeConstants.RESULT), resultAddress);
				translator.addProgramAddress(getProgram(MergeConstants.LATEST), latestAddress);
				translator.addProgramAddress(getProgram(MergeConstants.MY), myAddress);
				translator.addProgramAddress(getProgram(MergeConstants.ORIGINAL), originalAddress);

				mergePanel.setAddressTranslator(translator);

				mergePanel.goTo(resultAddress, MergeConstants.RESULT);
				mergePanel.goTo(latestAddress, MergeConstants.LATEST);
				mergePanel.goTo(myAddress, MergeConstants.MY);
				mergePanel.goTo(originalAddress, MergeConstants.ORIGINAL);

				mergePanel.validate();
			}
		});
		inputReceived = false;

		// block until the user takes action
		waitForInput();
	}

	/**
	 * Remove the listing merge panel from the merge manager.
	 */
	public void removeListingMergePanel() {
		SwingUtilities.invokeLater(() -> {
			showMergeTool();
			if (!isShowingListingMergePanel) {
				return;
			}
			mergePanel.removeDomainObjectListener();
			mergeTool.removePlugins(new Plugin[] { listingPlugin, goToPlugin });
			isShowingListingMergePanel = false;
			mergePlugin.showDefaultComponent();
		});
	}

	/**
	 * Returns the listing merge panel. This is the panel containing the four
	 * listing windows: result, latest, my, and original. The four listings are
	 * the center component of JPanel with a BorderLayout.
	 */
	public ListingMergePanel getListingMergePanel() {
		return mergePanel;
	}

	/**
	 * Determines if the modal merge tool is currently displayed on the screen.
	 * @return true if the merge tool is displayed.
	 */
	@Override
	public boolean isMergeToolVisible() {
		return mergeToolIsVisible;
	}

	/**
	 * Determines if the four program Listing merge panel is currently displayed in the merge tool.
	 * @return true if the Listing merge panel is displayed.
	 */
	public boolean isShowingListingMergePanel() {
		return isShowingListingMergePanel;
	}

}

class MergeNavigatable implements Navigatable {

	private final ListingMergePanel mergePanel;

	MergeNavigatable(ListingMergePanel mergePanel) {
		this.mergePanel = mergePanel;
	}

	@Override
	public void addNavigatableListener(NavigatableRemovalListener listener) {
		// stub
	}

	@Override
	public ProgramSelection getSelection() {
		return mergePanel.getFocusedListingPanel().getProgramSelection();
	}

	@Override
	public ProgramSelection getHighlight() {
		return mergePanel.getFocusedListingPanel().getProgramHighlight();
	}

	@Override
	public String getTextSelection() {
		return mergePanel.getFocusedListingPanel().getTextSelection();
	}

	@Override
	public long getInstanceID() {
		return 0;
	}

	@Override
	public ProgramLocation getLocation() {
		return mergePanel.getFocusedListingPanel().getProgramLocation();
	}

	@Override
	public LocationMemento getMemento() {
		return new LocationMemento(getProgram(), getLocation());
	}

	@Override
	public Icon getNavigatableIcon() {
		return null;
	}

	@Override
	public Program getProgram() {
		return mergePanel.getFocusedProgram();
	}

	@Override
	public boolean goTo(Program program, ProgramLocation location) {
		mergePanel.goTo(location, true);
		return true;
	}

	@Override
	public boolean isConnected() {
		return false;
	}

	@Override
	public boolean supportsMarkers() {
		return false;
	}

	@Override
	public boolean isDisposed() {
		return false;
	}

	@Override
	public boolean isVisible() {
		return mergePanel.getFocusedListingPanel().isVisible();
	}

	@Override
	public void removeNavigatableListener(NavigatableRemovalListener listener) {
	}

	@Override
	public void requestFocus() {
		mergePanel.getFocusedListingPanel().requestFocus();
	}

	@Override
	public void setHighlight(ProgramSelection highlight) {
		mergePanel.getFocusedListingPanel().setHighlight(highlight);
	}

	@Override
	public boolean supportsHighlight() {
		return true;
	}

	@Override
	public void setMemento(LocationMemento memento) {
	}

	@Override
	public void setSelection(ProgramSelection selection) {
		mergePanel.getFocusedListingPanel().setSelection(selection);
	}

	@Override
	public void removeHighlightProvider(HighlightProvider highlightProvider, Program program) {
		// currently unsupported
	}

	@Override
	public void setHighlightProvider(HighlightProvider highlightProvider, Program program) {
		// currently unsupported

	}
}
