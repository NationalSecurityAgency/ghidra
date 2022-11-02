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

import ghidra.app.events.*;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

/**
 * Base class to handle common program events: Program Open/Close, Program Activated,
 * Program Location, Program Selection, and Program Highlight.   This class has fields related to
 * these events: {@code currentProgram}, {@code currentLocation}, {@code currentSelection} and
 * {@code currentHighlight}.
 * <p>
 * Subclasses should override the following methods if they are interested in the corresponding
 * events:
 * <ul>
 *	<LI> {@link #programOpened(Program)}
 * 	<LI> {@link #programClosed(Program)}
 * 	<LI> {@link #locationChanged(ProgramLocation)}
 * 	<LI> {@link #selectionChanged(ProgramSelection)}
 * 	<LI> {@link #highlightChanged(ProgramSelection)}
 * </ul>
 */
public abstract class ProgramPlugin extends Plugin {

	protected Program currentProgram;
	protected ProgramLocation currentLocation;
	protected ProgramSelection currentSelection;
	protected ProgramSelection currentHighlight;

	/**
	 * Constructs a new program plugin
	 * @param plugintool tool        the parent tool for this plugin
	 */
	public ProgramPlugin(PluginTool plugintool) {
		super(plugintool);
		internalRegisterEventConsumed(ProgramActivatedPluginEvent.class);
		internalRegisterEventConsumed(ProgramLocationPluginEvent.class);
		internalRegisterEventConsumed(ProgramSelectionPluginEvent.class);
		internalRegisterEventConsumed(ProgramHighlightPluginEvent.class);
		internalRegisterEventConsumed(ProgramOpenedPluginEvent.class);
		internalRegisterEventConsumed(ProgramClosedPluginEvent.class);
	}

	/**
	 * Calling this constructor is works the same as calling {@link ProgramPlugin}.
	 *
	 * @deprecated call {@link #ProgramPlugin(PluginTool)} instead
	 * @param plugintool the tool
	 * @param consumeLocationChange not used
	 * @param consumeSelectionChange not used
	 */
	@Deprecated(forRemoval = true, since = "10.2")
	public ProgramPlugin(PluginTool plugintool, boolean consumeLocationChange,
			boolean consumeSelectionChange) {
		this(plugintool);
	}

	/**
	 * Calling this constructor is works the same as calling {@link ProgramPlugin}.
	 *
	 * @deprecated call {@link #ProgramPlugin(PluginTool)} instead
	 * @param plugintool the tool
	 * @param consumeLocationChange not used
	 * @param consumeSelectionChange not used
	 * @param consumeHighlightChange not used
	 */
	@Deprecated(forRemoval = true, since = "10.2")
	public ProgramPlugin(PluginTool plugintool, boolean consumeLocationChange,
			boolean consumeSelectionChange, boolean consumeHighlightChange) {
		this(plugintool);
	}

	/**
	 * Process the plugin event.
	 * <p>
	 * When a program closed event or focus changed event comes in, the locationChanged() and
	 * selectionChanged() methods are called with null arguments; currentProgram and
	 * currentLocation are cleared.
	 * <p>
	 * Note: if the subclass overrides processEvent(), it should call super.processEvent().
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
			}
			if (currentProgram != null) {
				programActivated(currentProgram);
			}

		}
		else if (event instanceof ProgramLocationPluginEvent) {

			ProgramLocationPluginEvent ev = (ProgramLocationPluginEvent) event;
			currentLocation = ev.getLocation();
			if (currentLocation != null && currentLocation.getAddress() == null ||
				(currentProgram == null && ev.getProgram() == null)) {
				currentLocation = null;
			}
			if (currentProgram == null) {
				// currentProgram is null because we haven't gotten the open program event yet (a
				// plugin is firing location change in response to open program that we haven't
				// gotten yet)
				return;
			}
			locationChanged(currentLocation);
		}
		else if (event instanceof ProgramSelectionPluginEvent) {
			ProgramSelectionPluginEvent ev = (ProgramSelectionPluginEvent) event;
			currentSelection = ev.getSelection();
			if (currentSelection != null && currentSelection.isEmpty()) {
				currentSelection = null;
			}
			selectionChanged(currentSelection);
		}
		else if (event instanceof ProgramHighlightPluginEvent) {
			ProgramHighlightPluginEvent ev = (ProgramHighlightPluginEvent) event;
			currentHighlight = ev.getHighlight();
			if (currentHighlight != null && currentHighlight.isEmpty()) {
				currentHighlight = null;
			}
			highlightChanged(currentHighlight);
		}
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
		// override
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
		// override

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
		// override

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
		// override
	}

	/**
	 * Subclass should override this method if it is interested in
	 * program location events.
	 * @param loc location could be null
	 */
	protected void locationChanged(ProgramLocation loc) {
		// override
	}

	/**
	 * Subclass should override this method if it is interested in
	 * program selection events.
	 * @param sel selection could be null
	 */
	protected void selectionChanged(ProgramSelection sel) {
		// override
	}

	/**
	 * Subclass should override this method if it is interested in
	 * program highlight events.
	 * @param hl highlight could be null
	 */
	protected void highlightChanged(ProgramSelection hl) {
		// override
	}

	/**
	 * Convenience method to go to the specified address.
	 * @param addr the address to go to
	 * @return true if successful
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
