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
package ghidra.app.merge.listing;

import java.awt.BorderLayout;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;

import javax.swing.*;

import docking.widgets.EmptyBorderButton;
import docking.widgets.button.GRadioButton;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.internal.FieldPanelCoordinator;
import docking.widgets.label.GIconLabel;
import ghidra.app.merge.MergeConstants;
import ghidra.app.merge.MergeManager;
import ghidra.app.merge.util.ConflictCountPanel;
import ghidra.app.plugin.core.codebrowser.hover.*;
import ghidra.app.services.CodeFormatService;
import ghidra.app.util.viewer.field.RegisterFieldFactory;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.app.util.viewer.listingpanel.*;
import ghidra.app.util.viewer.multilisting.AddressTranslator;
import ghidra.app.util.viewer.multilisting.MultiListingLayoutModel;
import ghidra.app.util.viewer.util.TitledPanel;
import ghidra.framework.data.DomainObjectMergeManager;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import resources.ResourceManager;
import resources.icons.EmptyIcon;

/**
 * Panel to select a data type in order to resolve an add conflict in the multi-user 
 * external location merger.
 */
class ExternalAddConflictPanel extends JPanel implements CodeFormatService {

	public static final String KEEP_LATEST_BUTTON_NAME = ListingMergeConstants.LATEST_BUTTON_NAME;
	public static final String KEEP_MY_BUTTON_NAME = ListingMergeConstants.CHECKED_OUT_BUTTON_NAME;
	public static final String KEEP_BOTH_BUTTON_NAME = ExternalFunctionMerger.KEEP_BOTH_BUTTON_NAME;
	public static final String MERGE_BOTH_BUTTON_NAME =
		ExternalFunctionMerger.MERGE_BOTH_BUTTON_NAME;

	private static Icon hideIcon = ResourceManager.loadImage("images/collapse.gif");
	private static Icon showIcon = ResourceManager.loadImage("images/expand.gif");

	private DomainObjectMergeManager mergeManager;
	private int totalConflicts;
	private ConflictCountPanel countPanel;
	private TitledPanel latestTitlePanel;
	private TitledPanel myTitlePanel;
	private ListingPanel latestPanel;
	private ListingPanel myPanel;
	private JRadioButton keepLatestRB;
	private JRadioButton keepMyRB;
	private JRadioButton keepBothRB;
	private JRadioButton mergeBothRB;
	private ButtonGroup buttonGroup;
	private JComponent bottomComp;
	private Program latestProgram;
	private Program myProgram;

	private PluginTool tool;
	private FormatManager formatMgr;
	private MultiListingLayoutModel multiModel;
	private ReferenceListingHover referenceHoverService;
	private DataTypeListingHover dataTypeHoverService;
	private TruncatedTextListingHover truncatedTextHoverService;
	private FunctionNameListingHover functionNameHoverService;
	private boolean showListingPanel;

	ExternalAddConflictPanel(MergeManager mergeManager, int totalConflicts, Program latestProgram,
			Program myProgram, boolean showListingPanel) {
		super();
		this.tool = mergeManager.getMergeTool();
		this.mergeManager = mergeManager;
		this.totalConflicts = totalConflicts;
		this.latestProgram = latestProgram;
		this.myProgram = myProgram;
		this.showListingPanel = showListingPanel;

		create();
		initializeListingHoverService();
	}

	private void initializeListingHoverService() {

		// The CodeFormatService is needed by the ReferenceHover.
		referenceHoverService = new ReferenceListingHover(tool, this);
		dataTypeHoverService = new DataTypeListingHover(tool);
		truncatedTextHoverService = new TruncatedTextListingHover(tool);
		functionNameHoverService = new FunctionNameListingHover(tool);

		initializeListingHoverService(latestPanel);
		initializeListingHoverService(myPanel);
	}

	private void initializeListingHoverService(ListingPanel listingPanel) {
		listingPanel.addHoverService(referenceHoverService);
		listingPanel.addHoverService(dataTypeHoverService);
		listingPanel.addHoverService(truncatedTextHoverService);
		listingPanel.addHoverService(functionNameHoverService);
		listingPanel.setHoverMode(true);
	}

	void setConflictInfo(int conflictIndex, ExternalLocation latestLocation,
			ExternalLocation myLocation) {

		mergeManager.setApplyEnabled(false);
		countPanel.updateCount(conflictIndex, totalConflicts);

		Address latestAddress = latestLocation.getExternalSpaceAddress();
		Address myAddress = myLocation.getExternalSpaceAddress();
		AddressSet latestSet = new AddressSet(latestAddress, latestAddress);
		AddressSet mySet = new AddressSet(myAddress, myAddress);
		latestPanel.setView(latestSet);
		myPanel.setView(mySet);

		buttonGroup.remove(keepLatestRB);
		buttonGroup.remove(keepMyRB);
		buttonGroup.remove(keepBothRB);
		buttonGroup.remove(mergeBothRB);

		keepLatestRB.setSelected(false);
		keepMyRB.setSelected(false);
		keepBothRB.setSelected(false);
		mergeBothRB.setSelected(false);

		buttonGroup.add(keepLatestRB);
		buttonGroup.add(keepMyRB);
		buttonGroup.add(keepBothRB);
		buttonGroup.add(mergeBothRB);
	}

	int getSelectedOption() {
		if (keepLatestRB.isSelected()) {
			return ExternalFunctionMerger.KEEP_LATEST_ADD;
		}
		if (keepMyRB.isSelected()) {
			return ExternalFunctionMerger.KEEP_MY_ADD;
		}
		if (keepBothRB.isSelected()) {
			return ExternalFunctionMerger.KEEP_BOTH_ADDS;
		}
		if (mergeBothRB.isSelected()) {
			return ExternalFunctionMerger.MERGE_BOTH_ADDS;
		}
		return ListingMergeConstants.ASK_USER; // shouldn't get here 
	}

	private ToolOptions getFieldOptions() {
		ToolOptions fieldOptions = new ToolOptions("field");
		fieldOptions.setBoolean(RegisterFieldFactory.DISPLAY_HIDDEN_REGISTERS_OPTION_NAME, true);
		return fieldOptions;
	}

	private ToolOptions getDisplayOptions() {
		return new ToolOptions("display");
	}

	private void create() {

		formatMgr = new FormatManager(getDisplayOptions(), getFieldOptions());
		multiModel = new MultiListingLayoutModel(formatMgr,
			new Program[] { latestProgram, myProgram }, latestProgram.getMemory());

		latestPanel = new ListingPanel(formatMgr, new EmptyListingModel()) {
			@Override
			protected ListingModel createListingModel(Program program) {
				if (program == null) {
					return null;
				}

				if (showListingPanel) {
					return multiModel.getAlignedModel(0);
				}
				return new EmptyListingModel();
			}
		};

		myPanel = new ListingPanel(formatMgr, new EmptyListingModel()) {
			@Override
			protected ListingModel createListingModel(Program program) {
				if (program == null) {
					return null;
				}

				if (showListingPanel) {
					return multiModel.getAlignedModel(1);
				}
				return new EmptyListingModel();
			}
		};

		latestPanel.setProgram(latestProgram);
		myPanel.setProgram(myProgram);

		new FieldPanelCoordinator(
			new FieldPanel[] { latestPanel.getFieldPanel(), myPanel.getFieldPanel() });

		buttonGroup = new ButtonGroup();
		ItemListener listener = e -> {
			if (e.getStateChange() == ItemEvent.SELECTED) {
				mergeManager.clearStatusText();
				mergeManager.setApplyEnabled(true);
			}
		};

		keepLatestRB = new GRadioButton(MergeConstants.LATEST_TITLE);
		keepLatestRB.setName(KEEP_LATEST_BUTTON_NAME);
		keepLatestRB.addItemListener(listener);

		keepMyRB = new GRadioButton(MergeConstants.MY_TITLE);
		keepMyRB.setName(KEEP_MY_BUTTON_NAME);
		keepMyRB.addItemListener(listener);

		keepBothRB = new GRadioButton("Both");
		keepBothRB.setName(KEEP_BOTH_BUTTON_NAME);
		keepBothRB.addItemListener(listener);

		mergeBothRB = new GRadioButton("Merge");
		mergeBothRB.setName(MERGE_BOTH_BUTTON_NAME);
		mergeBothRB.addItemListener(listener);

		buttonGroup.add(keepLatestRB);
		buttonGroup.add(keepMyRB);
		buttonGroup.add(keepBothRB);
		buttonGroup.add(mergeBothRB);

		setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

		countPanel = new ConflictCountPanel();

		JPanel centerPanel = new JPanel(new BorderLayout());
		latestTitlePanel = new TitledPanel(MergeConstants.LATEST_TITLE, latestPanel, 5);
		myTitlePanel = new TitledPanel(MergeConstants.MY_TITLE, myPanel, 5);

		latestTitlePanel.addTitleComponent(new ShowHeaderButton());
		myTitlePanel.addTitleComponent(new GIconLabel(new EmptyIcon(22, 22)));

		JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
		splitPane.setResizeWeight(0.5);
		splitPane.setDividerSize(4);
		splitPane.setBorder(BorderFactory.createEmptyBorder());
		splitPane.setLeftComponent(latestTitlePanel);
		splitPane.setRightComponent(myTitlePanel);
		centerPanel.add(splitPane, BorderLayout.CENTER);

		setLayout(new BorderLayout());
		add(countPanel, BorderLayout.NORTH);
		add(centerPanel, BorderLayout.CENTER);
	}

	public void setBottomComponent(JComponent comp) {
		if (bottomComp == comp) {
			return;
		}
		if (bottomComp != null) {
			remove(bottomComp);
		}

		invalidate();
		repaint(); // Since we are removing this while the panel is on the screen.

		bottomComp = comp;
		if (bottomComp != null) {
			add(bottomComp, BorderLayout.SOUTH);
		}
		invalidate();
		repaint();
	}

	class ShowHeaderButton extends EmptyBorderButton {
		ShowHeaderButton() {
			super(showIcon);
			setFocusable(false);
			setToolTipText("Toggle Format Header");
			addActionListener(e -> {
				if (isSelected()) {
					setSelected(false);
					setIcon(showIcon);
					latestPanel.showHeader(false);
				}
				else {
					setSelected(true);
					setIcon(hideIcon);
					latestPanel.showHeader(true);
				}
			});
		}
	}

	/**
	 * Add the latest program's listing model as a listener to the latest program 
	 * for domain object events.
	 */
	public void addDomainObjectListener() {
		DomainObjectListener listingModel = (DomainObjectListener) multiModel.getModel(0);
		latestProgram.addListener(listingModel);
	}

	/**
	 * Remove the latest program's listing model as a listener to the latest program 
	 * for domain object events.
	 */
	public void removeDomainObjectListener() {
		DomainObjectListener listingModel = (DomainObjectListener) multiModel.getModel(0);
		latestProgram.removeListener(listingModel);
	}

	public void setAddressTranslator(AddressTranslator translator) {
		multiModel.setAddressTranslator(translator);
	}

	@Override
	public FormatManager getFormatManager() {
		return formatMgr;
	}
}
