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
package ghidra.app.plugin.core.searchmem.mask;

import docking.action.MenuData;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.context.NavigatableContextAction;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.MemorySearchService;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

/**
 * Defines a set of actions that can be performed on a selection to initiate a memory search.  All
 * actions will ultimately open the {@code MemSearchDialog} with the search string field 
 * pre-populated.
 * 
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Search for Matching Instructions",
	description = "This plugin will use the selected instructions and build a combined "
			+ "mask/value buffer. Memory is then searched looking for this combined "
			+ "value buffer that represents the selected instructions. This automates "
			+ "the process of searching through memory for a particular ordering of "
			+ "instructions by hand.",
	servicesRequired = { MemorySearchService.class },
	eventsConsumed = { ProgramSelectionPluginEvent.class }
)
//@formatter:on
public class MnemonicSearchPlugin extends Plugin {

	static final String MENU_PULLRIGHT = "For Matching Instructions";
	static final String POPUP_MENU_GROUP = "Search";

	// Actions (accessible via Tools menu)
	private NavigatableContextAction setSearchMnemonicOpsNoConstAction;
	private NavigatableContextAction setSearchMnemonicOpsConstAction;
	private NavigatableContextAction setSearchMnemonicNoOpsNoConstAction;

	// Final bit string used to populate the memory search dialog.
	public String maskedBitString;

	/**
	 * Constructor.
	 * 
	 * @param tool the tool
	 */
	public MnemonicSearchPlugin(PluginTool tool) {
		super(tool);
		createActions();
	}

	/*
	 * Retrieves the selection region from the program, builds the search string, and pops
	 * up the MemSearchDialog
	 */
	private void processAction(NavigatableActionContext context, boolean useOps,
			boolean useConsts) {

		NavigatableActionContext newContext =
			(NavigatableActionContext) context.getContextObject();

		// Grab the program and selection from the context.
		Program program = newContext.getProgram();
		ProgramSelection selection = newContext.getSelection();

		// If there are multiple regions selected, let the user know via popup and 
		// exit.  This is not allowed.  
		// Note: We could disable the menu items and not allow this operation to 
		//       be initiated at all, but the decision was made to do it this way 
		//       so it's more obvious to the user why the operation is invalid.
		if (selection.getNumAddressRanges() > 1) {
			Msg.showInfo(this, context.getComponentProvider().getComponent(),
				"Mnemonic Search Error",
				"Multiple selected regions are not allowed; please limit to one.");
			return;
		}

		// Store the mask information (this is based solely on the menu action
		// that initiated this whole operation.
		SLMaskControl maskControl = new SLMaskControl(useOps, useConsts);
		MaskGenerator generator = new MaskGenerator(maskControl);
		MaskValue mask = generator.getMask(program, selection);

		// Now build the search string and set up the search service.  This preps the mem search
		// dialog with the proper search string.
		if (mask != null) {
			maskedBitString = createMaskedBitString(mask.getValue(), mask.getMask());
			byte[] maskedBytes = maskedBitString.getBytes();

			MemorySearchService memorySearchService =
				tool.getService(MemorySearchService.class);
			memorySearchService.setIsMnemonic(true);
			memorySearchService.search(maskedBytes, newContext);
			memorySearchService.setSearchText(maskedBitString);
		}
	}

	/**
	 * Create the menu action objects and defines click behavior for each.
	 */
	private void createActions() {

		String group = "search for";
		String pullRightGroup = "0"; // top of 'search for' group
		tool.setMenuGroup(new String[] { "&Search", MENU_PULLRIGHT }, group, pullRightGroup);

		HelpLocation helpLocation = new HelpLocation(HelpTopics.SEARCH, "Mnemonic_Search");

		//
		// ACTION 1: Search for instructions, excluding constants. 
		//
		setSearchMnemonicOpsNoConstAction =
			new NavigatableContextAction("Include Operands (except constants)", getName()) {

				@Override
				public void actionPerformed(NavigatableActionContext context) {
					processAction(context, true, false);
				}

				@Override
				protected boolean isEnabledForContext(NavigatableActionContext context) {
					return context.hasSelection();
				}

			};

		setSearchMnemonicOpsNoConstAction.setMenuBarData(new MenuData(new String[] { "&Search",
			MENU_PULLRIGHT, "Include Operands (except constants)" }, null, group,
			MenuData.NO_MNEMONIC, "3"));
		setSearchMnemonicOpsNoConstAction.setHelpLocation(helpLocation);
		setSearchMnemonicOpsNoConstAction
				.addToWindowWhen(NavigatableActionContext.class);

		//
		// ACTION 2: Search for instructions, including operands. 
		//
		setSearchMnemonicOpsConstAction =
			new NavigatableContextAction("Include Operands", getName()) {

				@Override
				public void actionPerformed(NavigatableActionContext context) {
					processAction(context, true, true);
				}

				@Override
				protected boolean isEnabledForContext(NavigatableActionContext context) {
					return context.hasSelection();
				}
			};

		setSearchMnemonicOpsConstAction.setMenuBarData(new MenuData(new String[] { "&Search",
			MENU_PULLRIGHT, "Include Operands" }, null, group, MenuData.NO_MNEMONIC, "2"));
		setSearchMnemonicOpsConstAction.setHelpLocation(helpLocation);
		setSearchMnemonicOpsConstAction
				.addToWindowWhen(NavigatableActionContext.class);

		//
		// ACTION 3: Search for instructions, excluding constants. 
		//
		setSearchMnemonicNoOpsNoConstAction =
			new NavigatableContextAction("Exclude Operands", getName()) {

				@Override
				public void actionPerformed(NavigatableActionContext context) {
					processAction(context, false, false);
				}

				@Override
				protected boolean isEnabledForContext(NavigatableActionContext context) {
					return context.hasSelection();
				}
			};

		setSearchMnemonicNoOpsNoConstAction.setMenuBarData(new MenuData(new String[] { "&Search",
			MENU_PULLRIGHT, "Exclude Operands" }, null, group, MenuData.NO_MNEMONIC, "1"));
		setSearchMnemonicNoOpsNoConstAction.setHelpLocation(helpLocation);
		setSearchMnemonicNoOpsNoConstAction
				.addToWindowWhen(NavigatableActionContext.class);

		// Add the actions to the tool...
		tool.addAction(setSearchMnemonicOpsNoConstAction);
		tool.addAction(setSearchMnemonicOpsConstAction);
		tool.addAction(setSearchMnemonicNoOpsNoConstAction);

		// ...and set in the menu group.
		tool.setMenuGroup(new String[] { MENU_PULLRIGHT }, POPUP_MENU_GROUP);
	}

	/*
	 * Returns a single string based on the masked bits
	 */
	private String createMaskedBitString(byte values[], byte masks[]) {

		String bitString = new String();

		//check that value and mask lengths are equal
		if (values.length != masks.length) {
			return null;
		}

		//pull the bits out of each byte and create search string
		for (int i = 0; i < values.length; i++) {
			for (int j = 0; j < 8; j++) {
				if (((masks[i] >> (7 - j)) & 1) == 0) {
					bitString = bitString.concat(".");
				}
				else if (((values[i] >> (7 - j)) & 1) == 0) {
					bitString = bitString.concat("0");
				}
				else {
					bitString = bitString.concat("1");
				}
			}
			bitString = bitString.concat(" ");
		}

		return bitString;
	}

}
