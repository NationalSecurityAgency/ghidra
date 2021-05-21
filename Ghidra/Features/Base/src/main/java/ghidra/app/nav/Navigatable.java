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
package ghidra.app.nav;

import javax.swing.Icon;

import ghidra.app.util.HighlightProvider;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

/**
 * Interface for ComponentProviders to implement if they support basic navigation and selection
 * capabilities.  Implementing this interface will provide the provider with navigation history
 * and actions that require navigation or selection. (Search Text, Search Memory, Select bytes,
 * Select instructions, etc.)
 */
public interface Navigatable {
	public static final long DEFAULT_NAVIGATABLE_ID = -1;

	public long getInstanceID();

	/**
	 * Commands this navigatable to goto (display) the given program and location
	 * @param program the program
	 * 
	 * @param location the location in that program to display
	 * @return true if the goto was successful
	 */
	public boolean goTo(Program program, ProgramLocation location);

	/**
	 * Returns the current location of this Navigatable
	 * @return the current location of this Navigatable
	 */
	public ProgramLocation getLocation();

	/**
	 * Returns the current Program of this Navigatable
	 * @return the current Program of this Navigatable
	 */
	public Program getProgram();

	/**
	 * Returns the view state for this navigatable
	 * @return the view state for this navigatable
	 */
	public LocationMemento getMemento();

	/** 
	 * Sets the view state for this navigatable.  This is used later to restore the view state.
	 * 
	 * @param memento the state of this navigatable
	 */
	public void setMemento(LocationMemento memento);

	/**
	 * Returns an icon that represents this Navigatable
	 * @return the icon
	 */
	public Icon getNavigatableIcon();

	/**
	 * Returns true if this Navigatable is "connected".  Navigatables are connected if they
	 * produce and consume location and selection events.
	 * 
	 * @return true if this Navigatable is "connected"
	 */
	public boolean isConnected();

	/**
	 * Currently only the 'connected' windows support markers
	 * @return true if this navigatable supports markers
	 */
	public boolean supportsMarkers();

	/**
	 * Tells this provider to request focus.
	 */
	public void requestFocus();

	/**
	 * Returns true if this provider is visible
	 * @return true if visible
	 */
	public boolean isVisible();

	/**
	 * Tells this Navigatable to set its selection to the given selection
	 * @param selection the selection to set.
	 */
	public void setSelection(ProgramSelection selection);

	/**
	 * Tells this Navigatable to set its highlight to the given highlight
	 * 
	 * @param highlight the highlight to set.
	 */
	public void setHighlight(ProgramSelection highlight);

	/**
	 * Returns the current selection of this Navigatable
	 * @return the current selection of this Navigatable
	 */
	public ProgramSelection getSelection();

	/**
	 * Returns the current highlight of this Navigatable
	 * @return the current highlight of this Navigatable
	 */
	public ProgramSelection getHighlight();

	/**
	 * Returns the current text selection or null
	 * @return the text selection
	 */
	public String getTextSelection();

	/**
	 * Adds a listener to be notified if this Navigatable is terminated
	 * @param listener the listener to be notified when this Navigatable is closed
	 */
	public void addNavigatableListener(NavigatableRemovalListener listener);

	/**
	 * Removes a listener to be notified if this Navigatable is terminated.
	 * @param listener the listener that no longer should be notified when this Navigatable is 
	 *        closed.
	 */
	public void removeNavigatableListener(NavigatableRemovalListener listener);

	/**
	 * Returns true if this navigatable is no longer valid, false if it is still good
	 * @return true if this navigatable is no longer valid, false if it is still good
	 */
	public boolean isDisposed();

	/**
	 * Returns true if this navigatable supports highlighting
	 * @return true if this navigatable supports highlighting
	 */
	public boolean supportsHighlight();

	/**
	 * Set the highlight provider for the given program
	 * 
	 * @param highlightProvider the provider
	 * @param program the program
	 */
	public void setHighlightProvider(HighlightProvider highlightProvider, Program program);

	/**
	 * Removes the given highlight provider for the given program
	 * 
	 * @param highlightProvider the provider
	 * @param program the program
	 */
	public void removeHighlightProvider(HighlightProvider highlightProvider, Program program);
}
