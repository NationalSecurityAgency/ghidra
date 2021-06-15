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
package ghidra.app.plugin.core.byteviewer;

import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.util.*;
import java.util.concurrent.CopyOnWriteArraySet;

import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.ActionContext;
import docking.ComponentProvider;
import ghidra.app.services.ClipboardContentProviderService;
import ghidra.app.util.ByteCopier;
import ghidra.app.util.ClipboardType;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.task.TaskMonitor;

public class ByteViewerClipboardProvider extends ByteCopier
		implements ClipboardContentProviderService {

	private static final List<ClipboardType> COPY_TYPES = createCopyTypesList();

	private static List<ClipboardType> createCopyTypesList() {
		List<ClipboardType> copyTypesList = new LinkedList<>();
		copyTypesList.add(BYTE_STRING_TYPE);
		copyTypesList.add(BYTE_STRING_NO_SPACE_TYPE);
		copyTypesList.add(PYTHON_BYTE_STRING_TYPE);
		copyTypesList.add(PYTHON_LIST_TYPE);
		copyTypesList.add(CPP_BYTE_ARRAY_TYPE);
		return copyTypesList;
	}

	private boolean copyEnabled;
	private boolean pasteEnabled;
	private Set<ChangeListener> listeners = new CopyOnWriteArraySet<>();
	private final ProgramByteViewerComponentProvider provider;

	public ByteViewerClipboardProvider(ProgramByteViewerComponentProvider provider,
			PluginTool tool) {
		this.provider = provider;
		this.tool = tool;
	}

	@Override
	public void addChangeListener(ChangeListener listener) {
		listeners.add(listener);
	}

	@Override
	public void removeChangeListener(ChangeListener listener) {
		listeners.remove(listener);
	}

	private void notifyStateChanged() {
		ChangeEvent event = new ChangeEvent(this);
		for (ChangeListener listener : listeners) {
			listener.stateChanged(event);
		}
	}

	@Override
	public boolean paste(Transferable pasteData) {
		try {
			// try the default paste
			return pasteBytes(pasteData);
		}
		catch (Exception e) {
			tool.setStatusInfo("Paste failed: " + e.getMessage(), true);
		}
		return false;
	}

	@Override
	public List<ClipboardType> getCurrentCopyTypes() {
		if (copyEnabled) {
			return COPY_TYPES;
		}
		return EMPTY_LIST;
	}

	@Override
	public Transferable copy(TaskMonitor monitor) {
		String byteString = copyBytesAsString(currentSelection, true, monitor);
		String textSelection = getTextSelection();
		return new ByteStringTransferable(byteString, textSelection);
	}

	protected String getTextSelection() {
		return provider.getCurrentTextSelection();
	}

	@Override
	public Transferable copySpecial(ClipboardType copyType, TaskMonitor monitor) {
		return copyBytes(copyType, monitor);
	}

	private void updateEnablement() {
		copyEnabled = (currentSelection != null && !currentSelection.isEmpty());
		notifyStateChanged();
	}

	void setLocation(ProgramLocation location) {
		currentLocation = location;
	}

	void setSelection(ProgramSelection selection) {
		currentSelection = selection;
		updateEnablement();
	}

	void setProgram(Program p) {
		currentProgram = p;
		currentLocation = null;
		currentSelection = null;
	}

	@Override
	public boolean isValidContext(ActionContext context) {
		return context.getComponentProvider() == provider;
	}

	@Override
	public ComponentProvider getComponentProvider() {
		return provider;
	}

	@Override
	public boolean enableCopy() {
		return true;
	}

	@Override
	public boolean enableCopySpecial() {
		return true;
	}

	@Override
	public boolean canCopy() {
		return copyEnabled;
	}

	@Override
	public boolean canCopySpecial() {
		return copyEnabled;
	}

	@Override
	public boolean enablePaste() {
		return true;
	}

	boolean isPasteEnabled() {
		return pasteEnabled;
	}

	void setPasteEnabled(boolean pasteEnabled) {
		this.pasteEnabled = pasteEnabled;
		notifyStateChanged();
	}

	@Override
	public boolean canPaste(DataFlavor[] availableFlavors) {
		if (!pasteEnabled) {
			return false;
		}
		if (availableFlavors != null) {
			for (DataFlavor flavor : availableFlavors) {
				if (flavor.equals(DataFlavor.stringFlavor)) {
					return true;
				}
			}
		}
		return false;
	}

//==================================================================================================
// Unsupported Operations
//==================================================================================================    

	@Override
	public void lostOwnership(Transferable transferable) {
		// no-op
	}
}
