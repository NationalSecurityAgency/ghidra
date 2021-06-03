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
 * Adapter class that receives notifications in order to
 * provide drag over effects.
 * <p> When the operation ends, this class receives a
 * <code>dragDropEnd</code> message, and is responsible for
 * checking the success of the operation. If the operation was
 * successful, and if it was a Move, then
 * this class will remove the source data.
 */
public class DragSrcAdapter implements DragSourceListener {
    protected Draggable dragComponent;

    private Cursor currentCursor;
    private Cursor copyDropCursor=DragSource.DefaultCopyDrop;
    private Cursor copyNoDropCursor=DragSource.DefaultCopyNoDrop;
    private Cursor moveDropCursor =DragSource.DefaultMoveDrop;
    private Cursor moveNoDropCursor=DragSource.DefaultMoveNoDrop;
    private Cursor linkDropCursor =DragSource.DefaultLinkDrop;
    private Cursor linkNoDropCursor = DragSource.DefaultLinkNoDrop;

    /**
     * Constructor
     * @param dragComponent component that can be dragged.
     */
    public DragSrcAdapter(Draggable dragComponent) {
        this.dragComponent = dragComponent;
    }
    /**
     * Called when the drag-drop operation completes.
     * Calls the drag component's move() method if the action is a
     * move operation.
     */
    public void dragDropEnd(DragSourceDropEvent e) {

        if (!e.getDropSuccess()) {
            dragComponent.dragCanceled(e);
//            DragGestureAdapter.clearTransferable();
            return;
        }
        int dropOp = e.getDropAction();
        int dragAction = dragComponent.getDragAction();

        if ((dropOp & DnDConstants.ACTION_MOVE) == DnDConstants.ACTION_MOVE &&
            (dragAction & DnDConstants.ACTION_MOVE) != 0) {
            dragComponent.move();
//            DragGestureAdapter.clearTransferable();
        }
    }
    /**
     * Called as the hotspot enters a platform dependent drop site.
     */
    public void dragEnter(DragSourceDragEvent e) {

        setDragOverFeedback(e);
    }
    /**
     * Called as the hotspot moves over a platform dependent drop site.
     */
    public void dragOver(DragSourceDragEvent e) {

        setDragOverFeedback(e);
    }

    /**
     * Called as the hotspot exits a platform dependent drop site.
     */
    public void dragExit(DragSourceEvent e) {

        DragSourceContext context = e.getDragSourceContext();
        context.setCursor(null); // bug workaround
        currentCursor = copyNoDropCursor;
        context.setCursor(currentCursor);
    }
    /**
     * Drop action changed, i.e., ctrl key pressed during drag to
     * change to a copy operation.
     */
    public void dropActionChanged(DragSourceDragEvent e) {
        setDragOverFeedback(e);
    }

    //////////////////////////////////////////////////////////////////////
    // *** private methods ***
    //////////////////////////////////////////////////////////////////////

    /**
     * Sets the cursor according to the actions that are legal.
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
                c = linkNoDropCursor;
            }
            else if ((dropOp & DnDConstants.ACTION_MOVE) == DnDConstants.ACTION_MOVE) {
                c = moveNoDropCursor;
            }
            else {
                c = copyNoDropCursor;
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
		Cursor c;
		if ((action & DnDConstants.ACTION_LINK) == DnDConstants.ACTION_LINK) {
		    c = linkDropCursor;
		}
		else if ((action & DnDConstants.ACTION_MOVE) == DnDConstants.ACTION_MOVE) {
		    c = moveDropCursor;
		}
		else {
		    c = copyDropCursor;
		}
		return c;
	}
}
