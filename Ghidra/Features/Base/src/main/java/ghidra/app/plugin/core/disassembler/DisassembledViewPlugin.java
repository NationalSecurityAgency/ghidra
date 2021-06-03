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
package ghidra.app.plugin.core.disassembler;

import java.awt.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.event.ChangeListener;

import docking.WindowPosition;
import docking.widgets.list.GListCellRenderer;
import ghidra.GhidraOptions;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.viewer.field.BrowserCodeUnitFormat;
import ghidra.app.util.viewer.field.FieldFactory;
import ghidra.app.util.viewer.options.OptionsGui;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.*;
import ghidra.util.exception.UsrException;

/**
 * A plugin to disassemble the address at the current ProgramLocation and to 
 * display the Instruction.  This work of this plugin is temporary in that it
 * will not change the state of the program.
 * 
 * 
 * 
 *  TODO Change the PseudoCodeUnit's getComment(int) method or change its 
 *       getPreview(int) method not to call getComment(int) and then change
 *       this class to not handle the UnsupportedOperationException.
 *  TODO are the category and names correct?
 *  TODO decide how to represent multiple selections in the display
 * 
 *  TODO Potential user options:
 *       -look ahead count
 *       -to or to not display multiple selections
 *       -change the format of the preview displayed
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Show Disassembled View",
	description = "This plugin shows the disassembled address at the " +
			"current ProgramLocation and displays the Instruction.  This " +
			"work of this plugin is temporary in that it will not change " +
			"the state of the program."
)
//@formatter:on
public class DisassembledViewPlugin extends ProgramPlugin implements DomainObjectListener {
	/**
	 * The number of addresses that should be disassembled, including the 
	 * address of the current {@link ProgramLocation}.
	 */
	private static final int LOOK_AHEAD_COUNT = 5;

	/**
	 * The component provider that this plugin uses.
	 */
	private DisassembledViewComponentProvider displayComponent =
		new DisassembledViewComponentProvider();

	/**
	 * The last program location received from the 
	 * {@link #locationChanged(ProgramLocation)} method.
	 */
	private ProgramLocation lastUpdatedLocation;

	/**
	 * This is the pseudo disassembler used by this class to produce a code
	 * unit for addresses that have not yet been disassembled.
	 */
	private PseudoDisassembler pseudoDisassembler;

	/**
	 * Constructor to initialize and register as an event listener.
	 * 
	 * @param plugintool The PluginTool required to initialize this plugin.
	 */
	public DisassembledViewPlugin(PluginTool plugintool) {
		// We want to know about program activated events, location changed
		// events and selection changed events.  The first type we get from
		// our parent, the other two we get by passing true to our parent's 
		// constructor
		super(plugintool, true, true);
	}

	/**
	 * Initialization method.
	 */
	@Override
	protected void init() {
		super.init();

		tool.addComponentProvider(displayComponent, false);
	}

	/**
	 * Cleanup method.
	 */
	@Override
	protected void dispose() {
		tool.removeComponentProvider(displayComponent);

		displayComponent.dispose();

		super.dispose();
	}

	/**
	 * Overridden in order to add ourselves as a {@link DomainObjectListener}
	 * to the current program.
	 * 
	 * @param program The activated program.
	 */
	@Override
	protected void programActivated(Program program) {

		program.addListener(this);
	}

	/**
	 * We want to make sure that we no longer have any contents when the 
	 * program is deactivated so that we do not make any more calls to the 
	 * program or its plugins.
	 * 
	 * @param program The program being deactivated.
	 * @see ProgramPlugin#programDeactivated(Program)
	 */
	@Override
	protected void programDeactivated(Program program) {
		program.removeListener(this);
		displayComponent.clearContents();
		pseudoDisassembler = null;
	}

	/* (non-Javadoc)
	 * @see ghidra.framework.model.DomainObjectListener#domainObjectChanged(ghidra.framework.model.DomainObjectChangedEvent)
	 */
	@Override
	public void domainObjectChanged(DomainObjectChangedEvent event) {
		// reset the view of the disassembled data
		if (displayComponent.isVisible()) {
			disassembleLocation(currentLocation);
		}
	}

	/**
	 * Generate and display the Instruction for the current ProgramLocation.
	 * 
	 * @param loc The current program location.
	 * @see ProgramPlugin#locationChanged(ProgramLocation)
	 */
	@Override
	protected void locationChanged(ProgramLocation loc) {
		// we only want to update if:
		// 1) we have a valid location,
		// 2) the location is different than the last location we processed, and
		//    TODO: **Note: this step is believed to be a bug--we should only be 
		//            getting one location change at a time, not two
		// 3) the display is visible.
		if (loc == null || loc.equals(lastUpdatedLocation) || !displayComponent.isVisible()) {
			return;
		}

		disassembleLocation(loc);
	}

	private boolean containsMultipleSelection() {
		if (currentSelection != null) {
			if (!currentSelection.isEmpty()) {
				return (currentSelection.getNumAddresses() > 1);
			}
		}
		return false;
	}

	/**
	 * Called when we receive program selection events.
	 * 
	 * @param selection The ProgramSelection object that is the current 
	 *        selection.
	 * @see ProgramPlugin#selectionChanged(ProgramSelection)
	 */
	@Override
	protected void selectionChanged(ProgramSelection selection) {
		if (!displayComponent.isVisible()) {
			return;
		}

		// TODO:
		// if there are multiple lines selected then we need to update the 
		// display.  Should we:
		// 1) Show each line selected with some sort of visual delimiter 
		//    between each value?
		// 2) Clear the display when there are multiple values selected?
		// 3) Do nothing and allow selections, while showing only the current
		//    location as determined by the cursor?
		// 
		// Currently solution 3) is used        
		if (selection != null) {
			if (containsMultipleSelection()) {
				disassembleLocation(currentLocation);
// changed in SCR 6875                
//                displayComponent.clearContents();
			}
			else if (selection.isEmpty()) {
				disassembleLocation(currentLocation);
			}
		}
		else {
			if (currentLocation != null) {
				disassembleLocation(currentLocation);
			}
		}
	}

	/**
	 * Gets the pseudo disassembler used by this class.  This method will lazy
	 * load the disassembler to prevent wasting of resources.  If the 
	 * program location changes, then the disassembler will be recreated.
	 * 
	 * @return the pseudo disassembler used by this class.
	 */
	private PseudoDisassembler getPseudoDisassembler() {
		if (pseudoDisassembler == null) {
			pseudoDisassembler = new PseudoDisassembler(currentProgram);
		}
		return pseudoDisassembler;
	}

	/**
	 * Gets the {@link DisassembledAddressInfo}s for the given address.  
	 * This method will disassamble {@link #LOOK_AHEAD_COUNT a few} addresses 
	 * after the one that is passed in.
	 * 
	 * @param  address The address for which an info object will be obtained.
	 * @return An array of info objects describing the initial address and any
	 *         others that could be obtained.
	 */
	private DisassembledAddressInfo[] getAddressInformation(Address address) {
		List<DisassembledAddressInfo> infoList = new ArrayList<>();

		if (address != null) {
			try {
				DisassembledAddressInfo addressInfo = new DisassembledAddressInfo(address);

				// Now get some follow-on addresses to provide a small level of 
				// context.  This loop will stop if we cannot find an Address
				// or a CodeUnit for a given address.
				for (int i = 0; (i < LOOK_AHEAD_COUNT) && (address != null) &&
					addressInfo.isValidAddress(); i++) {
					infoList.add(addressInfo);

					// Increment the address for the next code unit preview.
					// This call throws an AddressOverflowException
					address = address.addNoWrap(addressInfo.getCodeUnitLength());

					if (address != null) {
						addressInfo = new DisassembledAddressInfo(address);
					}
				}
			}
			catch (AddressOverflowException aoe) {
				// we don't really care because there is nothing left to show
				// here, as we've reached the end of the address space
			}
		}

		return infoList.toArray(new DisassembledAddressInfo[infoList.size()]);
	}

	/**
	 * Takes the provided program location object and locates a 
	 * {@link CodeUnit} for it's address that is used to display a disassembled
	 * preview of the location.
	 * 
	 * @param newLocation The program location to disassemble.
	 */
	private void disassembleLocation(ProgramLocation newLocation) {
		if (newLocation != null) {
			lastUpdatedLocation = newLocation;

			DisassembledAddressInfo[] addressInfos =
				getAddressInformation(newLocation.getAddress());

			// add our preview content to our display (this will be empty if we 
			// did not get a valid address or any valid code unit previews)
			displayComponent.setContents(addressInfos);
		}
	}

	/**
	 * The component provided for the DisassembledViewPlugin.
	 */
	private class DisassembledViewComponentProvider extends ComponentProviderAdapter {
		/**
		 * Constant for the selection color setting.
		 */

		/**
		 * Constant for the address foreground color setting.
		 */
		private static final String ADDRESS_COLOR_OPTION = "Address Color";

		/**
		 * Constant for the browser font setting.
		 */
		private static final String ADDRESS_FONT_OPTION = "BASE FONT";
		/**
		 * Constant for the browser's background setting.
		 */
		private static final String BACKGROUND_COLOR_OPTION = "Background Color";

		/**
		 * The constant part of the tooltip text for the list cells.  This
		 * string is prepended to the currently selected address in the 
		 * program.
		 * <p>
		 * Note: This value was just set on the list, but when that was done
		 * the help key triggers (Ctrl-F1) did not work correctly.
		 */
		private static final String TOOLTIP_TEXT_PREPEND =
			"<HTML>Currently selected<br> Code Browser program location<br>" + "address: ";

		/**
		 * The component that will house our view.
		 */
		private JComponent component;

		/**
		 * The list that will render the disassembled addresses.
		 */
		private JList<DisassembledAddressInfo> contentList;

		/**
		 * The color of the address in the list that represents the current
		 * selection in the code browser.
		 */
		private Color selectedAddressColor;

		/**
		 * The color of the preview text.
		 */
		private Color addressForegroundColor;

		/**
		 * The color for the list background.
		 */
		private Color backgroundColor;

		/**
		 * The font for the list items.
		 */
		private Font font;

		/**
		 * The preview style of the addresses being displayed.
		 */
		private BrowserCodeUnitFormat addressPreviewFormat;

		/**
		 * The listener that will be notified of changes to the user display
		 * settings.  We save this so that we can remove it during disposal.
		 */
		private OptionsChangeListener optionsChangeListener = new DisassembledViewOptionsListener();

		/**
		 * The location of the help file for this component.
		 */
		private HelpLocation pluginHelpLocation = new HelpLocation(
			DisassembledViewPlugin.this.getName(), DisassembledViewPlugin.this.getName());

		private ChangeListener addressFormatChangeListener = e -> contentList.repaint();

		/**
		 * Constructor for initialization.
		 */
		private DisassembledViewComponentProvider() {
			super(DisassembledViewPlugin.this.getTool(),
				"Virtual Disassembler - Current Instruction",
				DisassembledViewPlugin.this.getName());
			setTitle("Disassembled View");
			setHelpLocation(pluginHelpLocation);
			setDefaultWindowPosition(WindowPosition.BOTTOM);
			contentList = new JList<>();
			JScrollPane scrollPane = new JScrollPane(contentList);
			component = scrollPane;

			contentList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

			initializeDisplay();

			// we need to do some custom rendering
			contentList.setCellRenderer(new GListCellRenderer<DisassembledAddressInfo>() {

				@Override
				protected String getItemText(DisassembledAddressInfo value) {
					return value.getAddressPreview(addressPreviewFormat);
				}

				@Override
				public Component getListCellRendererComponent(
						JList<? extends DisassembledAddressInfo> list,
						DisassembledAddressInfo value, int index, boolean isSelected,
						boolean cellHasFocus) {

					super.getListCellRendererComponent(list, value, index, isSelected,
						cellHasFocus);

					setFont(font);

					setToolTipText(TOOLTIP_TEXT_PREPEND +
						HTMLUtilities.escapeHTML(currentLocation.getAddress().toString()));

					// make sure the first value is highlighted to indicate
					// that it is the selected program location
					if (index == 0) {
						Color foreground = addressForegroundColor;
						Color background = selectedAddressColor;

						if (isSelected) {
							foreground = foreground.brighter();
							background = background.darker();
						}

						setForeground(foreground);
						setBackground(background);
					}

					return this;
				}
			});
		}

		/**
		 * Initializes the colors and font of the display.
		 */
		private void initializeDisplay() {
			// setup the colors that we will use to paint the entries
			ToolOptions opt = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
			opt.addOptionsChangeListener(optionsChangeListener);

			// current address background color
			selectedAddressColor = opt.getColor(GhidraOptions.OPTION_SELECTION_COLOR,
				GhidraOptions.DEFAULT_SELECTION_COLOR);

			// the address preview style
			addressPreviewFormat = new BrowserCodeUnitFormat(tool);
			addressPreviewFormat.addChangeListener(addressFormatChangeListener);

			opt = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_DISPLAY);
			opt.addOptionsChangeListener(optionsChangeListener);

			// the preview text color
			addressForegroundColor = opt.getColor(OptionsGui.SEPARATOR.getColorOptionName(),
				OptionsGui.SEPARATOR.getDefaultColor());

			// background color
			backgroundColor = opt.getColor(OptionsGui.BACKGROUND.getColorOptionName(),
				OptionsGui.BACKGROUND.getDefaultColor());

			// font
			font = opt.getFont(ADDRESS_FONT_OPTION, FieldFactory.DEFAULT_FIELD_FONT);

			contentList.setForeground(addressForegroundColor);
			contentList.setBackground(backgroundColor);
			contentList.setFont(font);
		}

		/**
		 * Releases resources as necessary.
		 */
		void dispose() {
			// remove our listeners
			ToolOptions opt = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
			opt.removeOptionsChangeListener(optionsChangeListener);

			opt = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_DISPLAY);
			opt.removeOptionsChangeListener(optionsChangeListener);
		}

		/**
		 * Adds the given listener to be notified when the user selects list
		 * items in the view.
		 * 
		 * @param listener The listener to add.
		 */
//        void addListSelectionListener( ListSelectionListener listener )
//        {
//            contentList.addListSelectionListener( listener );
//        }

		/**
		 * Sets the contents to the provided value.
		 * 
		 * @param displayContents The value that the view should display.
		 */
		void setContents(DisassembledAddressInfo[] addressInfos) {
			contentList.setListData(addressInfos);
		}

		/**
		 * Clears the contents of the view.
		 */
		void clearContents() {
			contentList.setListData(new DisassembledAddressInfo[] {});
		}

		/**
		 * Gets the component that will house our view.
		 * 
		 * @return the component that will house our view.
		 */
		@Override
		public JComponent getComponent() {
			return component;
		}

		/**
		 * Notifies the provider that the user pressed the "close" button.  
		 * The provider should take appropriate action.  Usually the 
		 * appropriate action is to hide the component or remove the 
		 * component.  If the provider does nothing in this method, 
		 * then the close button will appear broken.
		 */
		@Override
		public void closeComponent() {
			super.closeComponent();
			clearContents();
		}

		/**
		 * Notifies the provider that the component is being hidden.
		 */
		@Override
		public void componentHidden() {
			clearContents();
		}

		/**
		 * Notifies the provider that the component is being shown.
		 */
		@Override
		public void componentShown() {
			// Update the contents with the current address
			disassembleLocation(currentLocation);
		}

		private class DisassembledViewOptionsListener implements OptionsChangeListener {
			@Override
			public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
					Object newValue) {
				if (options.getName().equals(GhidraOptions.CATEGORY_BROWSER_FIELDS)) {
					if (optionName.equals(GhidraOptions.OPTION_SELECTION_COLOR)) {
						selectedAddressColor = (Color) newValue;
					}
				}
				else if (options.getName().equals(GhidraOptions.CATEGORY_BROWSER_DISPLAY)) {
					if (optionName.equals(ADDRESS_COLOR_OPTION)) {
						addressForegroundColor = (Color) newValue;
						contentList.setForeground(addressForegroundColor);
					}
					else if (optionName.equals(BACKGROUND_COLOR_OPTION)) {
						backgroundColor = (Color) newValue;
						contentList.setBackground(backgroundColor);
					}
					else if (optionName.equals(ADDRESS_FONT_OPTION)) {
						font = (Font) newValue;
					}
				}

				// update the display
				contentList.repaint();
			}
		}
	}

	/**
	 * An object that provides information about the address that it wraps.
	 * The info knows how to locate a {@link CodeInfo} object for the address
	 * and can generate a string preview of the address.
	 */
	private class DisassembledAddressInfo {
		/**
		 * The address passed to this class in the beginning.
		 */
		private Address wrappedAddress;

		/**
		 * The code unit for the address of this info.  This will be null 
		 * after construction if not code unit exists for the address.
		 */
		private CodeUnit addressCodeUnit;

		/**
		 * Constructs a new info instance based upon the given address.
		 * <p>
		 * Note: A NullPointerException will be logged if <tt> address</tt> is
		 *       null.
		 * 
		 * @param  address The address that this info is based upon.
		 */
		private DisassembledAddressInfo(Address address) {
			if (address == null) {
				Msg.showError(this, displayComponent.getComponent(),
					"Disassembled View Plugin Exception", null, new NullPointerException(
						"Cannot construct a " + "DisassembledAddressInfo with a null address."));
			}

			wrappedAddress = address;
			addressCodeUnit = getCodeUnitForAddress(address);
		}

		/**
		 * Returns the address described by this info.
		 * 
		 * @return Returns the address described by this info. 
		 */
		private Address getAddress() {

			return wrappedAddress;
		}

		/**
		 * Returns true if there is a {@link CodeUnit} for the address 
		 * wrapped by this info.  If not, then we do not have a valid addreess.
		 * 
		 * @return true if there is a {@link CodeUnit} for the address 
		 *         wrapped by this info.
		 */
		public boolean isValidAddress() {
			return (addressCodeUnit != null);
		}

		/**
		 * Gets the length of the {@link CodeUnit} for the address wrapped 
		 * by this info.  
		 * <p>
		 * Note: If {@link #isValidAddress()} returns false, then this method
		 * will return <code>-1</code>.
		 * 
		 * @return the length of the code unit for the address wrapped by this 
		 *         info. 
		 */
		public int getCodeUnitLength() {
			if (isValidAddress()) {
				return addressCodeUnit.getLength();
			}

			return -1;
		}

		/**
		 * Get the code unit from the program location.
		 *
		 * @param  The address from which we want the CodeUnit.
		 * @return CodeUnit null if there is no location.
		 */
		private CodeUnit getCodeUnitForAddress(Address address) {
			CodeUnit codeUnit = null;

			if ((currentProgram != null) && (currentLocation != null)) {
				Listing listing = currentProgram.getListing();
				codeUnit = listing.getCodeUnitAt(address);

				// if the CodeUnit is Data and is not defined, then we 
				// need to try to virutally disassemble it
				if (codeUnit instanceof Data) {
					if (!((Data) codeUnit).isDefined()) {
						CodeUnit virtualCodeUnit = virtuallyDisassembleAddress(address);

						if (virtualCodeUnit != null) {
							codeUnit = virtualCodeUnit;
						}
					}
				}
			}

			return codeUnit;
		}

		/**
		 * Attempts to disassemble the provided address virtually 
		 * (without changing the state of the program) by making use of the 
		 * {@link PseudoDisassembler}.
		 * 
		 * @param  address The address that will be disassembled.
		 * @return The CodeUnit that resulted from the disassembly.
		 */
		private CodeUnit virtuallyDisassembleAddress(Address address) {
			CodeUnit codeUnit = null;

			if (address != null) {
				PseudoDisassembler disassembler = getPseudoDisassembler();

				try {
					codeUnit = disassembler.disassemble(address);
				}
				catch (UsrException ue) {
					// these exceptions happen if there is insufficient data
					// from the program: InsufficientBytesException, 
					// UnknownInstructionException, UnknownContextException
				}
			}

			return codeUnit;
		}

		/**
		 * Gets the preview String for the provided code unit.
		 */
		public String getAddressPreview(CodeUnitFormat format) {
			return getAddress().toString() + " " + format.getRepresentationString(addressCodeUnit);
		}
	}
}
