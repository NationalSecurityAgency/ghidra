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
package ghidra.app.plugin.core.terminal;

import java.awt.datatransfer.*;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.io.IOException;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;

import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import org.apache.commons.lang3.ArrayUtils;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.dnd.StringTransferable;
import docking.widgets.fieldpanel.support.FieldSelection;
import ghidra.app.services.ClipboardContentProviderService;
import ghidra.app.util.ClipboardType;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * The clipboard provider for the terminal plugin.
 * 
 * <p>
 * In addition to providing clipboard contents and paste functionality, this customizes the Copy and
 * Paste actions. We change the "owner" to be this plugin, so that the action can be configured
 * independently of the standard Copy and Paste actions. Then, we re-bind the keys to Ctrl+Shift+C
 * and Shift+Shift+V, respectively. This ensures that Ctrl+C will still send an Interrupt (char 3).
 * This is the convention followed by just about every XTerm clone.
 */
public class TerminalClipboardProvider implements ClipboardContentProviderService {
	protected static final ClipboardType TEXT_TYPE =
		new ClipboardType(DataFlavor.stringFlavor, "Text");
	protected static final List<ClipboardType> COPY_TYPES = List.of(TEXT_TYPE);

	protected final TerminalProvider provider;
	protected FieldSelection selection;

	protected final Set<ChangeListener> listeners = new CopyOnWriteArraySet<>();

	public TerminalClipboardProvider(TerminalProvider provider) {
		this.provider = provider;
	}

	@Override
	public ComponentProvider getComponentProvider() {
		return provider;
	}

	@Override
	public Transferable copy(TaskMonitor monitor) {
		if (selection == null || selection.getNumRanges() != 1) {
			return null;
		}
		String text = provider.panel.getSelectedText(selection.getFieldRange(0));
		if (text == null) {
			return null;
		}
		return new StringTransferable(text);
	}

	@Override
	public Transferable copySpecial(ClipboardType copyType, TaskMonitor monitor) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean paste(Transferable pasteData) {
		try {
			String text = (String) pasteData.getTransferData(DataFlavor.stringFlavor);
			provider.panel.paste(text);
			return true;
		}
		catch (UnsupportedFlavorException | IOException e) {
			return false;
		}
	}

	@Override
	public List<ClipboardType> getCurrentCopyTypes() {
		if (selection == null || selection.getNumRanges() == 0) {
			return List.of();
		}
		return COPY_TYPES;
	}

	@Override
	public boolean isValidContext(ActionContext context) {
		return context.getComponentProvider() == provider;
	}

	@Override
	public boolean enableCopy() {
		return true;
	}

	@Override
	public boolean enableCopySpecial() {
		return false;
	}

	@Override
	public boolean enablePaste() {
		return true;
	}

	@Override
	public void lostOwnership(Transferable transferable) {
		// Nothing to do
	}

	@Override
	public void addChangeListener(ChangeListener listener) {
		listeners.add(listener);
	}

	@Override
	public void removeChangeListener(ChangeListener listener) {
		listeners.remove(listener);
	}

	@Override
	public boolean canPaste(DataFlavor[] availableFlavors) {
		return -1 != ArrayUtils.indexOf(availableFlavors, DataFlavor.stringFlavor);
	}

	@Override
	public boolean canCopy() {
		return selection != null && selection.getNumRanges() == 1;
	}

	@Override
	public boolean canCopySpecial() {
		return false;
	}

	private void notifyStateChanged() {
		ChangeEvent event = new ChangeEvent(this);
		for (ChangeListener listener : listeners) {
			try {
				listener.stateChanged(event);
			}
			catch (Throwable t) {
				Msg.showError(this, null, "Error", t.getMessage(), t);
			}
		}
	}

	public void selectionChanged(FieldSelection selection) {
		this.selection = selection;
		notifyStateChanged();
	}

	@Override
	public String getClipboardActionOwner() {
		return provider.plugin.getName();
	}

	@Override
	public void customizeClipboardAction(DockingAction action) {
		switch (action.getName()) {
			case "Copy":
				action.setKeyBindingData(new KeyBindingData(KeyEvent.VK_C,
					InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK));
				break;
			case "Paste":
				action.setKeyBindingData(new KeyBindingData(KeyEvent.VK_V,
					InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK));
				break;
		}
	}
}
