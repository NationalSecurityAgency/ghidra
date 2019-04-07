/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.dnd.*;
import java.util.ArrayList;

/**
 * Class to handle notifications of drag and drop operations that occur
 * on the DropTarget object. The DropTarget is the component that accepts
 * drops during a drag and drop operation. The <tt>drop</tt>
 * method actually transfers the data.
 */
public class DropTgtAdapter implements DropTargetListener {

    private Droppable dropComponent;
    private int dropActions; // actions that the drop target
        // can accept
    private DataFlavor []dropFlavors; //drop flavors that the
        // drop target can accept

    /**
     * Constructor
     * @param dropComponent the drop target
     * @param acceptableDropActions a DnDConstants variable that defines
     * dnd actions
     * @param acceptableDropFlavors acceptable data formats that the drop
     * target can handle
     */
    public DropTgtAdapter(Droppable dropComponent,
        int acceptableDropActions, DataFlavor []acceptableDropFlavors) {

        this.dropComponent = dropComponent;
        dropActions = acceptableDropActions;
        dropFlavors = acceptableDropFlavors;
    }
    /**
     * Set the data flavors acceptable to the associated drop target.
     * @param dropFlavors
     */
    public void setAcceptableDropFlavors(DataFlavor []dropFlavors) {
    	this.dropFlavors = dropFlavors;
    }
    /**
     * DropTargetListener method called when the drag operation encounters
     * the drop target.
     * @param e event that has current state of drag and drop operation
     */
    public void dragEnter(DropTargetDragEvent e) {

        if (isDropOk(e)) {
            e.acceptDrag(e.getDropAction());
        }
        else {
            dropComponent.dragUnderFeedback(false,e);
            e.rejectDrag();
        }
    }
    /**
     * DropTargetListener method called when the drag operation is over
     * the drop target.
     * @param e event that has current state of drag and drop operation
     */
    public void dragOver(DropTargetDragEvent e) {

        if (isDropOk(e)) {
            dropComponent.dragUnderFeedback(true, e);
            e.acceptDrag(e.getDropAction());
        }
        else {
            dropComponent.dragUnderFeedback(false,e);
            e.rejectDrag();
        }
    }
    /**
     * DropTargetListener method called when the
     * drag operation exits the drop target without dropping.  However,
     * this method is also called even when the drop completes.
     * @param e event that has current state of drag and drop operation
     */
    public void dragExit(DropTargetEvent e) {
        dropComponent.undoDragUnderFeedback();
        // Note: at this point, there is no way to tell whether the
        // drop actually occurred; so, there is no notification
        // for a "drop canceled"

    }
    /**
     * DropTargetListener method called when the user modifies the
     * drag action.
     * @param e event that has current state of drag and drop operation
     */
    public void dropActionChanged(DropTargetDragEvent e){
        dragOver(e);
    }
    /**
     * DropTargetListener method called when the drag operation terminates and
     * drops onto the drop target.
     * @param e event that has current state of drag and drop operation
     */
    public void drop(DropTargetDropEvent e) {

        // only handle local transfers (within same JVM) for now...
//        if (!e.isLocalTransfer()) {
//            e.rejectDrop();
//            dropComponent.undoDragUnderFeedback();
//            return;
//        }

        Transferable t = e.getTransferable();
        int flavorIndex=-1;
        for (int i=0; i<dropFlavors.length; i++) {
            if (t.isDataFlavorSupported(dropFlavors[i])) {
                flavorIndex = i;
                break;
            }
        }
        if (flavorIndex < 0) {
            e.rejectDrop();
            dropComponent.undoDragUnderFeedback();
            return;
        }

        int dropAction = e.getDropAction();
        int sourceActions = e.getSourceActions();

        if ( (dropAction & sourceActions) == 0) {
            e.rejectDrop();
            dropComponent.undoDragUnderFeedback();
            return;
        }

        // the source listener receives this action in dragDropEnd().
        // if the action is DnDConstants.ACTION_COPY_OR_MOVE, then
        // the source receives the MOVE.
        e.acceptDrop(e.getDropAction());
        Object data =null;
        boolean error=false;
        Throwable th=null;

        // now get the drop flavor that matches up with that in
        // the transferable object

		try {
			data = t.getTransferData(dropFlavors[flavorIndex]);
		} catch (Throwable thr) {
			error=true;
			th = thr;
		}

        if (error) {
            e.dropComplete(false);
            dropComponent.undoDragUnderFeedback();
            Msg.showError(this,null, "Drop Failed", "Could not get transfer data.", th);
        }
        else {
            // this is the copy
            DataFlavor flavor=dropFlavors[flavorIndex];
            try {
                dropComponent.add(data, e, flavor);
                // notify drag source that the drop is complete...
                e.dropComplete(true);
                dropComponent.undoDragUnderFeedback();
            } catch (Throwable thr) {
                e.dropComplete(false);
                dropComponent.undoDragUnderFeedback();
                String message = thr.getMessage();
                if ( message == null ) {
                    message = "";
                }
                Msg.showError(this, null, "Unexpected Drag and Drop Exception", message, thr);
            }
        }

    }

    /**
     * Returns true if the drop operation is OK. A drop is deemed to be okay if
     * <br> 1. the drop target accepts one of the data flavors that the event's transferrable provides.
     * <br> 2. the drop action (i.e. COPY, MOVE, etc.) is accepted by the target.
     * <br> 3. the drop is accepted by the Droppable component.
     * @param e event that has current state of drag and drop operation
     */
    protected boolean isDropOk(DropTargetDragEvent e) {
		// Does this target accept the drop action type being dropped on it?
        int da = e.getDropAction();
        if ((da & dropActions) == 0) {
            return false;
        }
        // Does the event's transferable have a flavor that this drop target accepts?
		if (!isDragFlavorSupported(e)) {
        	return false;
        }
		// Does the target component allow the drop.
        if (!dropComponent.isDropOk(e)) {
        	return false;
        }
        return true;
    }
    /**
     * Returns true if the drop target can accept the data
     * flavor that is to be dropped.
     */
    protected boolean isDragFlavorSupported(DropTargetDragEvent e) {
        if (dropFlavors == null) {
            return false; // This drop target doesn't accept any flavors.
        }
        // Check each flavor to see that this accepts at least one flavor the event can drop.
        for (int i=0; i<dropFlavors.length; i++) {
            if (e.isDataFlavorSupported(dropFlavors[i])){
                return true;
            }
        }
        return false;
    }

	public static DataFlavor getFirstMatchingFlavor(DropTargetDragEvent e, DataFlavor[] acceptableFlavors) {
		DataFlavor[] transferFlavors = e.getCurrentDataFlavors();
		for (DataFlavor acceptableFlavor : acceptableFlavors) {
			for (DataFlavor transferFlavor : transferFlavors) {
				if (acceptableFlavor.equals(transferFlavor)) {
					return transferFlavor;
				}
            }
        }
        return null;
    }

	public static DataFlavor[] getAllMatchingFlavors(DropTargetDragEvent e, DataFlavor[] acceptableFlavors) {
		ArrayList<DataFlavor> list = new ArrayList<DataFlavor>();
		DataFlavor[] transferFlavors = e.getCurrentDataFlavors();
		for (DataFlavor acceptableFlavor : acceptableFlavors) {
			for (DataFlavor transferFlavor : transferFlavors) {
				if (acceptableFlavor.equals(transferFlavor)) {
					list.add(transferFlavor);
					break;
				}
			}
		}
		return list.toArray(new DataFlavor[list.size()]);
	}

}
