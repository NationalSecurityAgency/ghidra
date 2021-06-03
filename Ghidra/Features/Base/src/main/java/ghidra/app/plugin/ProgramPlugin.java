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
package ghidra.app.plugin;

import java.util.ArrayList;

import docking.ActionContext;
import docking.action.DockingAction;
import ghidra.app.events.*;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

/**
 * Base class to handle common program events: Program Open/Close,
 * Program Location, Program Selection, and Program Highlight. 
 * <p>
 * Subclasses should override the following methods if they are interested
 * in the corresponding events:
 * <ul>
 * <LI> <code>programOpened(Program)</code> 
 * <LI> <code>programClosed(Program)</code> 
 * <LI> <code>locationChanged(ProgramLocation)</code>
 * <LI> <code>selectionChanged(ProgramSelection) </code>
 * <LI> <code>highlightChanged(ProgramSelection) </code>
 * </LI>
 * </ul>
 * <br>
 * This class will handle the enablement and add to popup state for
 * plugin actions when subclasses call any of the following methods:
 * <ul>
 * <LI><code>enableOnHighlight(PluginAction)</code>
 * <LI><code>enableOnLocation(PluginAction)</code>
 * <LI><code>enableOnProgram(PluginAction)</code>
 * <LI><code>enableOnSelection(PluginAction)</code>
 * </LI>
 * </ul>
 *
 */
public abstract class ProgramPlugin extends Plugin {

	protected Program currentProgram;
	protected ProgramLocation currentLocation;
	protected ProgramSelection currentSelection;
	protected ProgramSelection currentHighlight;
	private ArrayList<DockingAction> programActionList;
	private ArrayList<DockingAction> locationActionList;
	private ArrayList<DockingAction> selectionActionList;
	private ArrayList<DockingAction> highlightActionList;

	/**
	 * Constructs a new program plugin
	 * @param plugintool tool        the parent tool for this plugin
	 * @param consumeLocationChange  true if this plugin should consume ProgramLocation events
	 * @param consumeSelectionChange true if this plugin should consume ProgramSelection events
	 * @param consumeHighlightChange true if this plugin should consume ProgramHighlight events
	 */
	public ProgramPlugin(PluginTool plugintool, boolean consumeLocationChange,
			boolean consumeSelectionChange, boolean consumeHighlightChange) {
		super(plugintool);
		registerEventConsumed(ProgramActivatedPluginEvent.class);

		if (consumeLocationChange) {
			//register most derived class
			registerEventConsumed(ProgramLocationPluginEvent.class);
		}
		if (consumeSelectionChange) {
			registerEventConsumed(ProgramSelectionPluginEvent.class);
		}
		if (consumeHighlightChange) {
			registerEventConsumed(ProgramHighlightPluginEvent.class);
		}
		registerEventConsumed(ProgramOpenedPluginEvent.class);
		registerEventConsumed(ProgramClosedPluginEvent.class);
		programActionList = new ArrayList<>(3);
		locationActionList = new ArrayList<>(3);
		selectionActionList = new ArrayList<>(3);
		highlightActionList = new ArrayList<>(3);
	}

	public ProgramPlugin(PluginTool tool, boolean consumeLocationChange,
			boolean consumeSelectionChange) {
		this(tool, consumeLocationChange, consumeSelectionChange, false);
	}

	/**
	 * Process the plugin event.
	 * When a program closed event or focus changed event comes in,
	 * the locationChanged() and selectionChanged() methods are called
	 * with null arguments; currentProgram and currentLocation are cleared.
	 * <p>Note: if the subclass overrides processEvent(), it should call
	 * super.processEvent().
	 */
	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramClosedPluginEvent) {
			ProgramClosedPluginEvent ev = (ProgramClosedPluginEvent) event;
			programClosed(ev.getProgram());
		}
		else if (event instanceof ProgramOpenedPluginEvent) {
			ProgramOpenedPluginEvent ev = (ProgramOpenedPluginEvent) event;
			programOpened(ev.getProgram());
		}
		else if (event instanceof ProgramActivatedPluginEvent) {
			ProgramActivatedPluginEvent ev = (ProgramActivatedPluginEvent) event;
			Program oldProgram = currentProgram;
			currentProgram = ev.getActiveProgram();
			if (oldProgram != null) {
				programDeactivated(oldProgram);
				currentLocation = null;
				currentSelection = null;
				currentHighlight = null;
				locationChanged(null);
				selectionChanged(null);
				highlightChanged(null);
				enableActions(locationActionList, false);
				enableActions(selectionActionList, false);
				enableActions(highlightActionList, false);
			}
			if (currentProgram != null) {
				programActivated(currentProgram);
			}
			enableActions(programActionList, currentProgram != null);

		}
		else if (event instanceof ProgramLocationPluginEvent) {

			ProgramLocationPluginEvent ev = (ProgramLocationPluginEvent) event;
			currentLocation = ev.getLocation();
			if (currentLocation != null && currentLocation.getAddress() == null ||
				(currentProgram == null && ev.getProgram() == null)) {
				currentLocation = null;
				// disable actions, but don't remove from popup
				enableActions(locationActionList, false);
			}
			else if (currentLocation == null) {
				// disable actions and remove from popup
				enableActions(locationActionList, false);
				// remove selection actions
			}
			else {
				// enable actions
				enableActions(locationActionList, true);
				// add selection actions
			}
			if (currentProgram == null) {
				// currentProgram is null because we haven't gotten the
				// open program event yet (a plugin is firing location change
				// in response to open program that we haven't gotten yet),
				// so just pull it out of the
				// location event...
				//currentProgram = ev.getProgram();
				//programOpened(currentProgram);
				return;
			}
			locationChanged(currentLocation);
		}
		else if (event instanceof ProgramSelectionPluginEvent) {
			ProgramSelectionPluginEvent ev = (ProgramSelectionPluginEvent) event;
			currentSelection = ev.getSelection();
			if (currentSelection != null && !currentSelection.isEmpty()) {
				enableActions(selectionActionList, true);
			}
			else {
				enableActions(selectionActionList, false);
				currentSelection = null;
			}
			selectionChanged(currentSelection);
		}
		else if (event instanceof ProgramHighlightPluginEvent) {
			ProgramHighlightPluginEvent ev = (ProgramHighlightPluginEvent) event;
			currentHighlight = ev.getHighlight();
			if (currentHighlight != null && !currentHighlight.isEmpty()) {
				enableActions(highlightActionList, true);
			}
			else {
				enableActions(highlightActionList, false);
				currentHighlight = null;
			}
			highlightChanged(currentHighlight);
		}
	}

	/**
	 * Enable the action when the program is opened; disable it when
	 * the program is closed.
	 * @throws IllegalArgumentException if this action was called for
	 * another enableOnXXX(PlugAction) method.
	 * @deprecated {@link ActionContext} is now used for action enablement.  Deprecated in 9.1; to
	 *             be removed no sooner than two versions after that.
	 */
	@Deprecated
	protected void enableOnProgram(DockingAction action) {
		if (locationActionList.contains(action)) {
			throw new IllegalArgumentException("Action already added to location action list");
		}
		if (selectionActionList.contains(action)) {
			throw new IllegalArgumentException("Action already added to selection action list");
		}
		if (highlightActionList.contains(action)) {
			throw new IllegalArgumentException("Action already added to highlight action list");
		}
		programActionList.add(action);
		action.setEnabled(currentProgram != null);
	}

	/**
	 * Enable the action when a program location event comes in; disable it
	 * if either the location is null, or if the address in the location
	 * is null.
	 * @throws IllegalArgumentException if this action was called for
	 * another enableOnXXX(PlugAction) method.
	 * @deprecated {@link ActionContext} is now used for action enablement.  Deprecated in 9.1; to
	 *             be removed no sooner than two versions after that.
	 */
	@Deprecated
	protected void enableOnLocation(DockingAction action) {
		if (programActionList.contains(action)) {
			throw new IllegalArgumentException("Action already added to program action list");
		}
		if (selectionActionList.contains(action)) {
			throw new IllegalArgumentException("Action already added to selection action list");
		}
		if (highlightActionList.contains(action)) {
			throw new IllegalArgumentException("Action already added to highlight action list");
		}

		locationActionList.add(action);
		action.setEnabled(currentLocation != null);
	}

	/**
	 * Enable the action when a selection event comes in; disable it if
	 * the selection is null or empty.
	 * @throws IllegalArgumentException if this action was called for
	 * another enableOnXXX(PlugAction) method.
	 * @deprecated {@link ActionContext} is now used for action enablement.  Deprecated in 9.1; to
	 *             be removed no sooner than two versions after that.
	 */
	@Deprecated
	protected void enableOnSelection(DockingAction action) {
		if (programActionList.contains(action)) {
			throw new IllegalArgumentException("Action already added to program action list");
		}
		if (locationActionList.contains(action)) {
			throw new IllegalArgumentException("Action already added to location action list");
		}
		if (highlightActionList.contains(action)) {
			throw new IllegalArgumentException("Action already added to highlight action list");
		}
		selectionActionList.add(action);
		action.setEnabled(currentSelection != null);
	}

	/**
	 * Enable the action when a highlight event comes in; disable it if
	 * the highlight is null or empty.
	 * @throws IllegalArgumentException if this action was called for
	 * another enableOnXXX(PlugAction) method.
	 * @deprecated {@link ActionContext} is now used for action enablement.  Deprecated in 9.1; to
	 *             be removed no sooner than two versions after that.
	 */
	@Deprecated
	protected void enableOnHighlight(DockingAction action) {
		if (programActionList.contains(action)) {
			throw new IllegalArgumentException("Action already added to program action list");
		}
		if (locationActionList.contains(action)) {
			throw new IllegalArgumentException("Action already added to location action list");
		}
		if (selectionActionList.contains(action)) {
			throw new IllegalArgumentException("Action already added to selection action list");
		}
		highlightActionList.add(action);
		action.setEnabled(currentHighlight != null);
	}

	/**
	 * Subclass should override this method if it is interested when programs become active.
	 * Note: this method is called in response to a ProgramActivatedPluginEvent. 
	 * 
	 * At the time this method is called, 
	 * the "currentProgram" variable will be set the new active program.
	 * 
	 * @param program the new program going active.
	 */
	protected void programActivated(Program program) {
	}

	/**
	 * Subclasses should override this method if it is interested when a program is closed.
	 * 
	 * This event has no affect on the "current Program".  A "programDeactivated" call will
	 * occur that affects the active program.
	 * 
	 * @param program the program being closed.
	 */
	protected void programClosed(Program program) {

	}

	/**
	 * Subclasses should override this method if it is interested when a program is opened.
	 * 
	 * This event has no affect on the "current Program".  A "programActivated" call will
	 * occur that affects the active program.
	 * 
	 * @param program the program being opened.
	 */
	protected void programOpened(Program program) {

	}

	/**
	 * Subclass should override this method if it is interested when programs become inactive.
	 * Note: this method is called in response to a ProgramActivatedPluginEvent and there is 
	 * a currently active program.
	 * 
	 * At the time this method is called, 
	 * the "currentProgram" variable will be set the 
	 * new active program or null if there is no new active program.
	 * 
	 * @param program the old program going inactive.
	 */
	protected void programDeactivated(Program program) {
	}

	/**
	 * Subclass should override this method if it is interested in
	 * program location events.
	 * @param loc location could be null
	 */
	protected void locationChanged(ProgramLocation loc) {
	}

	/**
	 * Subclass should override this method if it is interested in
	 * program selection events.
	 * @param sel selection could be null
	 */
	protected void selectionChanged(ProgramSelection sel) {
	}

	/**
	 * Subclass should override this method if it is interested in
	 * program highlight events.
	 * @param hl highlight could be null
	 */
	protected void highlightChanged(ProgramSelection hl) {
	}

	/**
	 * Convenience method to go to the specified address.
	 */
	protected boolean goTo(Address addr) {
		GoToService service = tool.getService(GoToService.class);
		if (service != null) {
			return service.goTo(addr);
		}
		return false;
	}

	protected boolean goTo(CodeUnit cu) {
		if (cu != null) {
			goTo(cu.getMinAddress());
		}
		return false;
	}

	/**
	 * Convenience method to fire a program selection event.
	 * @param set address set for the selection.
	 */
	protected void setSelection(AddressSetView set) {
		if (currentProgram == null) {
			return;
		}
		firePluginEvent(
			new ProgramSelectionPluginEvent(getName(), new ProgramSelection(set), currentProgram));
	}

	/**
	 * Convenience method to set a bookmark;
	 * @param addr address of where the bookmark will be placed
	 * @param type type of bookmark: BookMarkType.NOTE, BookmarkType.INFO,
	 * BookmarkType.ANALYSIS, or BookmarkType.ERROR.
	 * @param category category for the bookmark
	 * @param comment bookmark comment
	 */
	protected void setBookmark(Address addr, String type, String category, String comment) {
		if (currentProgram == null) {
			return;
		}
		BookmarkManager mgr = currentProgram.getBookmarkManager();
		int transactionID = currentProgram.startTransaction("Set Bookmark");

		try {
			mgr.setBookmark(addr, type, category, comment);
		}
		finally {
			currentProgram.endTransaction(transactionID, true);
		}
	}

	////////////////////////////////////////////////////////////////////

	/**
	 * Enable actions in the list according to the enabled param.
	 * @param enabled true means to enable the action AND set the
	 * add to popup as true; false means disable the action and set
	 * add to popup according to the removeFromPopup
	 * @param removeFromPopup only used if enabled is false
	 */
	private void enableActions(ArrayList<DockingAction> list, boolean enabled) {
		for (int i = 0; i < list.size(); i++) {
			DockingAction a = list.get(i);
			a.setEnabled(enabled);
		}
	}

	public ProgramLocation getProgramLocation() {
		return currentLocation;
	}

	public Program getCurrentProgram() {
		return currentProgram;
	}

	public ProgramSelection getProgramSelection() {
		return currentSelection;
	}

	public ProgramSelection getProgramHighlight() {
		return currentHighlight;
	}
}
