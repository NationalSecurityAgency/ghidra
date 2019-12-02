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

import java.awt.Point;
import java.awt.datatransfer.Transferable;
import java.awt.dnd.*;

/**
 * Interface to define a drag source.
 */
public interface Draggable {
    
    /**
     * Return true if the object at the location in the DragGesture 
	 * event is draggable.
	 *
	 * @param e event passed to a DragGestureListener via its 
	 * dragGestureRecognized() method when a particular DragGestureRecognizer 
	 * detects a platform dependent Drag and Drop action initiating 
	 * gesture has occurred on the Component it is tracking.  
	 * @see docking.dnd.DragGestureAdapter
     */
    public boolean isStartDragOk(DragGestureEvent e);
    
    /**
     * Called by the DragGestureAdapter to start the drag.
     */
    public DragSourceListener getDragSourceListener();
    
    /**
     * Do the move operation; called when the drag and drop operation
	 * completes.
	 * @see docking.dnd.DragSrcAdapter#dragDropEnd
     */
    public void move();
    
    /**
     * Method called when the drag operation exits the drop target 
     * without dropping.
     * @param event TODO
     */
    public void dragCanceled(DragSourceDropEvent event);

	/**
	 * Get the drag actions supported by this drag source:
	 * <UL>
	 * <li>DnDConstants.ACTION_MOVE
	 * <li>DnDConstants.ACTION_COPY
	 * <li>DnDConstants.ACTION_COPY_OR_MOVE
	 * </UL>
	 * 
	 * @return the drag actions
	 */
    public int getDragAction();
    
    /**
     * Get the object to transfer.
	 * @param p location of object to transfer
	 * @return object to transfer
     */
    public Transferable getTransferable(Point p);
}
