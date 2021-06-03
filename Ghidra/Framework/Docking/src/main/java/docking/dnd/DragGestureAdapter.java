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

import ghidra.util.Msg;

import java.awt.datatransfer.Transferable;
import java.awt.dnd.*;
import java.awt.event.InputEvent;

/**
 * This class receives notification when the user intitiates a
 * drag and drop operation; it is responsible for getting the
 * <code>Transferable</code> and telling the <code>DragSource</code> to 
 * start the drag.
 */
public class DragGestureAdapter implements DragGestureListener {
    
    private Draggable dragComponent;
//    private Cursor cursor = DragSource.DefaultCopyNoDrop;
//    private static Transferable transferable;

	/**
	 * Construct a new DragGestureAdapter
	 * 
	 * @param dragComponent Component that can support drag operations
	 */
    public DragGestureAdapter(Draggable dragComponent) {
        this.dragComponent = dragComponent;
    }
    
	/**
	 * A <code>DragGestureRecognizer</code> has detected a 
	 * platform-dependent Drag and Drop action initiating gesture
	 * and is notifying this Listener in order for it to initiate
	 * the action for the user.
	 * <p>The <code>DragGestureRecognizer</code> hides the platform-specific
	 * events that initate a drag and drop operation.
	 * 
	 * @param e event describing the gesture that has just occurred
	 */
    public void dragGestureRecognized(DragGestureEvent e) {

        // check input event: if any button other than MB1 is pressed,
        // don't attempt to process the drag and drop event.
        InputEvent ie = e.getTriggerEvent();
        int modifiers = ie.getModifiers();
        if ((modifiers & InputEvent.BUTTON2_MASK) != 0 ||
            (modifiers & InputEvent.BUTTON3_MASK) != 0) {
            return;
        }
        int dragAction = dragComponent.getDragAction();
        
        if ( ((e.getDragAction() & dragAction) == 0) || 
            !dragComponent.isStartDragOk(e)) {
            return;
        }
        
        Transferable t = dragComponent.getTransferable(e.getDragOrigin());
        
        DragSourceListener l = dragComponent.getDragSourceListener();
        if (t == null || l == null) {
            return;
        }
//        transferable = t;
        try {
            e.startDrag(DragSource.DefaultCopyNoDrop, t, l);
        } catch (InvalidDnDOperationException exc) {
            // the Drag and Drop system is unable to initiate a drag operation
            Msg.error(this, "Exception occurred during drag initiation: " + exc, exc);

            //            transferable = null;
        }
    }
    
//    /**
//     * Get the transferable that is being dragged.
//     */
//    static Transferable getTransferable() {
//        return transferable;
//    }
//    /**
//     * Clear the transferable object that is being dragged.
//     */
//    static void clearTransferable() {
//        transferable = null;
//    }
}
