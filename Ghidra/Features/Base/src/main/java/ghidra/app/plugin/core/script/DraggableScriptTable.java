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
package ghidra.app.plugin.core.script;

import java.awt.Point;
import java.awt.datatransfer.Transferable;
import java.awt.dnd.*;
import java.util.ArrayList;

import javax.swing.table.TableModel;

import docking.dnd.*;
import generic.jar.ResourceFile;
import ghidra.util.table.GhidraTable;

public class DraggableScriptTable extends GhidraTable implements Draggable {
	private DragSrcAdapter dragSourceAdapter;
	private DragGestureAdapter dragGestureAdapter;
	private DragSource dragSource;
	private final GhidraScriptComponentProvider provider;

	/**
	 * Constructs a new DraggableGhidraTable.
	 * @param provider the provider, from which getTableModel and getScriptAt are used
	 * @param model provider's table model
	 */
	public DraggableScriptTable(GhidraScriptComponentProvider provider, TableModel model) {
		super(model);
		this.provider = provider;

		initDragNDrop();
	}

	private void initDragNDrop() {
		// set up drag stuff
		dragSource = DragSource.getDefaultDragSource();
		dragGestureAdapter = new DragGestureAdapter(this);
		dragSourceAdapter = new DragSrcAdapter(this);
		dragSource.createDefaultDragGestureRecognizer(this, DnDConstants.ACTION_COPY_OR_MOVE,
			dragGestureAdapter);
	}

	/**
	 * Return true if the location in the event is draggable.
	 */
	@Override
	public boolean isStartDragOk(DragGestureEvent e) {
		return true;
	}

	/**
	 * Called by the DragGestureAdapter to start the drag.
	 */
	@Override
	public DragSourceListener getDragSourceListener() {
		return dragSourceAdapter;
	}

	/**
	 * Called by the DragGestureAdapter and the DragSourceAdapter to
	 * know what actions this component allows.
	 */
	@Override
	public int getDragAction() {
		return DnDConstants.ACTION_COPY_OR_MOVE;
	}

	/**
	 * Called by the DragGestureAdapter when the drag is about to
	 * start.
	 */
	@Override
	public Transferable getTransferable(Point p) {
		ArrayList<ResourceFile> arrayList = new ArrayList<>();
		int[] selectedRows = getSelectedRows();
		for (int element : selectedRows) {
			arrayList.add(provider.getScriptAt(element));
		}
		return new GhidraTransferable(arrayList);
	}

	/**
	 * Do the move operation. Called from the DragSourceAdapter
	 * when the drop completes and the user action was a
	 * DnDConstants.MOVE.
	 */
	@Override
	public void move() {
		//
	}

	/**
	 * Called from the DragSourceAdapter when the drag operation exits the
	 * drop target without dropping.
	 */
	@Override
	public void dragCanceled(DragSourceDropEvent event) {
		//
	}

}
