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
package ghidra.app.util;

import java.awt.Component;
import java.awt.Container;
import java.awt.datatransfer.DataFlavor;
import java.awt.dnd.*;
import java.awt.event.ContainerEvent;
import java.awt.event.ContainerListener;
import java.util.LinkedHashMap;
import java.util.Set;

import javax.swing.CellRendererPane;

import docking.DropTargetHandler;
import docking.dnd.DropTgtAdapter;
import docking.dnd.Droppable;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.CascadedDropTarget;

/**
 *  Handles drag/drop events on a given component such that a file
 *  dropped on the component from the front end tool will cause
 *  that file to be opened.  Properly handles drop events with
 *  child components and listens for components being added/removed
 *  in order to properly support drag/drop with all components.
 */
public class FileOpenDropHandler implements DropTargetHandler, Droppable, ContainerListener {

	// note: we wish to maintain insertion order
	private static LinkedHashMap<DataFlavor, FileOpenDataFlavorHandler> handlers =
		new LinkedHashMap<DataFlavor, FileOpenDataFlavorHandler>();

	private DropTgtAdapter dropTargetAdapter;
	private DropTarget globalDropTarget;

	private PluginTool tool;
	private Component component;

	/**
	 * Construct a new FileOpenDropHandler.
	 * @param tool plugin tool
	 * @param component component that is the drop target
	 */
	public FileOpenDropHandler(PluginTool tool, Component component) {
		this.tool = tool;
		this.component = component;

		Set<DataFlavor> keySet = handlers.keySet();
		DataFlavor[] handlersFlavorArray = keySet.toArray(new DataFlavor[keySet.size()]);
		dropTargetAdapter =
			new DropTgtAdapter(this, DnDConstants.ACTION_COPY_OR_MOVE, handlersFlavorArray);
		globalDropTarget =
			new DropTarget(component, DnDConstants.ACTION_COPY_OR_MOVE, dropTargetAdapter, true);
		initializeComponents(component);
	}

	/**
	 * Dispose this drop handler.
	 */
	@Override
	public void dispose() {
		deinitializeComponents(component);
		globalDropTarget.removeDropTargetListener(dropTargetAdapter);
	}

	@Override
	public boolean isDropOk(DropTargetDragEvent e) {
		Set<DataFlavor> flavors = handlers.keySet();
		for (DataFlavor dataFlavor : flavors) {
			if (e.isDataFlavorSupported(dataFlavor)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public void add(Object obj, DropTargetDropEvent e, DataFlavor f) {
		FileOpenDataFlavorHandler handler = handlers.get(f);
		if (handler != null) {
			handler.handle(tool, obj, e, f);
		}
	}

	@Override
	public void dragUnderFeedback(boolean ok, DropTargetDragEvent e) {
		// nothing to display or do
	}

	@Override
	public void undoDragUnderFeedback() {
		// nothing to display or do
	}

	private void initializeComponents(Component comp) {
		if (comp instanceof CellRendererPane) {
			return;
		}

		if (comp instanceof Container) {
			Container c = (Container) comp;
			c.addContainerListener(this);
			Component comps[] = c.getComponents();
			for (Component element : comps) {
				initializeComponents(element);
			}
		}
		DropTarget primaryDropTarget = comp.getDropTarget();
		if (primaryDropTarget != null) {
			new CascadedDropTarget(comp, primaryDropTarget, globalDropTarget);
		}
	}

	private void deinitializeComponents(Component comp) {
		if (comp instanceof CellRendererPane) {
			return;
		}

		if (comp instanceof Container) {
			Container c = (Container) comp;
			c.removeContainerListener(this);
			Component comps[] = c.getComponents();
			for (Component element : comps) {
				deinitializeComponents(element);
			}
		}
		DropTarget dt = comp.getDropTarget();
		if (dt instanceof CascadedDropTarget) {
			CascadedDropTarget target = (CascadedDropTarget) dt;
			DropTarget newTarget = target.removeDropTarget(globalDropTarget);
			comp.setDropTarget(newTarget);
		}
	}

	@Override
	public void componentAdded(ContainerEvent e) {
		initializeComponents(e.getChild());
	}

	@Override
	public void componentRemoved(ContainerEvent e) {
		deinitializeComponents(e.getChild());
	}

	public static void addDataFlavorHandler(DataFlavor dataFlavor,
			FileOpenDataFlavorHandler handler) {
		handlers.put(dataFlavor, handler);
	}

	public static FileOpenDataFlavorHandler removeDataFlavorHandler(DataFlavor dataFlavor) {
		return handlers.remove(dataFlavor);
	}
}
