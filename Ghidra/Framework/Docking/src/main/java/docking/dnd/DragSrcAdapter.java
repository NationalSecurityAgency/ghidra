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
package docking.dnd;

import java.awt.Cursor;
import java.awt.dnd.*;

/**
 * Adapter class that receives notifications in order to provide drag over effects.
 * 
 * <p>When the operation ends, this class receives a <code>dragDropEnd</code> message, and is 
 * responsible for checking the success of the operation. If the operation was successful, and if it
 * was a Move, then this class will remove the source data.
 */
public class DragSrcAdapter implements DragSourceListener {

	private static final Cursor COPY_DROP_CURSOR = DragSource.DefaultCopyDrop;
	private static final Cursor COPY_NO_DROP_CURSOR = DragSource.DefaultCopyNoDrop;
	private static final Cursor MOVE_DROP_CURSOR = DragSource.DefaultMoveDrop;
	private static final Cursor MOVE_NO_DROP_CURSOR = DragSource.DefaultMoveNoDrop;
	private static final Cursor LINK_DROP_CURSOR = DragSource.DefaultLinkDrop;
	private static final Cursor LINK_NO_DROP_CURSOR = DragSource.DefaultLinkNoDrop;

	private Cursor currentCursor;
	protected Draggable dragComponent;

	/**
	 * Constructor
	 * @param dragComponent component that can be dragged.
	 */
	public DragSrcAdapter(Draggable dragComponent) {
		this.dragComponent = dragComponent;
	}

	@Override
	public void dragDropEnd(DragSourceDropEvent e) {
		dragComponent.dragFinished(!e.getDropSuccess());
	}

	@Override
	public void dragEnter(DragSourceDragEvent e) {
		setDragOverFeedback(e);
	}

	@Override
	public void dragOver(DragSourceDragEvent e) {
		setDragOverFeedback(e);
	}

	@Override
	public void dragExit(DragSourceEvent e) {

		DragSourceContext context = e.getDragSourceContext();
		context.setCursor(null); // bug workaround
		currentCursor = COPY_NO_DROP_CURSOR;
		context.setCursor(currentCursor);
	}

	@Override
	public void dropActionChanged(DragSourceDragEvent e) {
		setDragOverFeedback(e);
	}

	/**
	 * Sets the cursor according to the actions that are legal.
	 * @param e the event
	 */
	protected void setDragOverFeedback(DragSourceDragEvent e) {
		DragSourceContext context = e.getDragSourceContext();
		int dropOp = e.getDropAction();
		int targetAction = e.getTargetActions();
		int action = dropOp & targetAction;
		Cursor c = null;

		if (action == DnDConstants.ACTION_NONE) {
			// drop not possible
			if ((dropOp & DnDConstants.ACTION_LINK) == DnDConstants.ACTION_LINK) {
				c = LINK_NO_DROP_CURSOR;
			}
			else if ((dropOp & DnDConstants.ACTION_MOVE) == DnDConstants.ACTION_MOVE) {
				c = MOVE_NO_DROP_CURSOR;
			}
			else {
				c = COPY_NO_DROP_CURSOR;
			}
		}
		else {
			// drop is possible
			c = getDropOkCursor(action);
		}

		context.setCursor(null); // bug workaround...
		currentCursor = c;
		context.setCursor(c);
	}

	/**
	 * Get the cursor for an "OK" drop.
	 * @param action action for the drag operation (copy, move, link)
	 * @return cursor that is appropriate for the give action
	 */
	protected Cursor getDropOkCursor(int action) {

		if ((action & DnDConstants.ACTION_LINK) == DnDConstants.ACTION_LINK) {
			return LINK_DROP_CURSOR;
		}
		else if ((action & DnDConstants.ACTION_MOVE) == DnDConstants.ACTION_MOVE) {
			return MOVE_DROP_CURSOR;
		}
		else {
			return COPY_DROP_CURSOR;
		}
	}
}
