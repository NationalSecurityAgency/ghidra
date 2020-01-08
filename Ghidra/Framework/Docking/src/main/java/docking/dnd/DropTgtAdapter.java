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

import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.dnd.*;

import ghidra.util.Msg;

/**
 * Class to handle notifications of drag and drop operations that occur on the DropTarget 
 * object. The DropTarget is the component that accepts drops during a drag and drop operation. 
 * The <code>drop</code> method actually transfers the data.
 */
public class DropTgtAdapter implements DropTargetListener {

	private Droppable dropComponent;
	private int dropActions; // actions that the drop target can accept
	private DataFlavor[] dropFlavors; //drop flavors that the drop target can accept

	/**
	 * Constructor
	 * 
	 * @param dropComponent the drop target
	 * @param acceptableDropActions a DnDConstants variable that defines dnd actions
	 * @param acceptableDropFlavors acceptable data formats that the drop target can handle
	 */
	public DropTgtAdapter(Droppable dropComponent,
			int acceptableDropActions, DataFlavor[] acceptableDropFlavors) {

		this.dropComponent = dropComponent;
		dropActions = acceptableDropActions;
		dropFlavors = acceptableDropFlavors;
	}

	/**
	 * Set the data flavors acceptable to the associated drop target
	 * @param dropFlavors the flavors
	 */
	public void setAcceptableDropFlavors(DataFlavor[] dropFlavors) {
		this.dropFlavors = dropFlavors;
	}

	@Override
	public void dragEnter(DropTargetDragEvent e) {

		if (isDropOk(e)) {
			e.acceptDrag(e.getDropAction());
		}
		else {
			dropComponent.dragUnderFeedback(false, e);
			e.rejectDrag();
		}
	}

	@Override
	public void dragOver(DropTargetDragEvent e) {

		if (isDropOk(e)) {
			dropComponent.dragUnderFeedback(true, e);
			e.acceptDrag(e.getDropAction());
		}
		else {
			dropComponent.dragUnderFeedback(false, e);
			e.rejectDrag();
		}
	}

	@Override
	public void dragExit(DropTargetEvent e) {
		dropComponent.undoDragUnderFeedback();

		// Note: at this point, there is no way to tell whether the drop actually occurred; 
		// so, there is no notification for a "drop canceled"
	}

	@Override
	public void dropActionChanged(DropTargetDragEvent e) {
		dragOver(e);
	}

	@Override
	public void drop(DropTargetDropEvent e) {

		Transferable t = e.getTransferable();
		int flavorIndex = -1;
		for (int i = 0; i < dropFlavors.length; i++) {
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

		if ((dropAction & sourceActions) == 0) {
			e.rejectDrop();
			dropComponent.undoDragUnderFeedback();
			return;
		}

		// The source listener receives this action in dragDropEnd().
		// If the action is DnDConstants.ACTION_COPY_OR_MOVE, then the source receives the MOVE.
		e.acceptDrop(e.getDropAction());
		Object data = null;

		try {
			data = t.getTransferData(dropFlavors[flavorIndex]);
		}
		catch (Throwable throwable) {
			e.dropComplete(false);
			dropComponent.undoDragUnderFeedback();
			Msg.showError(this, null, "Drop Failed", "Could not get transfer data.", throwable);
			return;
		}

		// this is the copy
		DataFlavor flavor = dropFlavors[flavorIndex];
		try {
			dropComponent.add(data, e, flavor);
			e.dropComplete(true);
			dropComponent.undoDragUnderFeedback();
		}
		catch (Throwable throwable) {
			e.dropComplete(false);
			dropComponent.undoDragUnderFeedback();
			String message = throwable.getMessage();
			Msg.showError(this, null, "Unexpected Drag and Drop Exception", message, throwable);
		}

	}

	/**
	 * Returns true if the drop operation is OK. A drop is deemed to be okay if
	 * <OL>
	 * 	<LI>the drop target accepts one of the data flavors that the event's transferable provides
	 * 	</LI>
	 * 	<LI>the drop action (i.e. COPY, MOVE, etc.) is accepted by the target
	 * 	</LI>
	 * 	<LI>the drop is accepted by the Droppable component
	 * 	</LI>
	 * </OL>
	 * 
	 * @param e event that has current state of drag and drop operation
	 * @return true if the drop operation is OK
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
	 * Returns true if the drop target can accept the data flavor that is to be dropped
	 * @param e event that has current state of drag and drop operation
	 * @return true if the drop target can accept the data flavor that is to be dropped
	 */
	protected boolean isDragFlavorSupported(DropTargetDragEvent e) {
		if (dropFlavors == null) {
			return false; // This drop target doesn't accept any flavors.
		}
		// Check each flavor to see that this accepts at least one flavor the event can drop.
		for (DataFlavor dropFlavor : dropFlavors) {
			if (e.isDataFlavorSupported(dropFlavor)) {
				return true;
			}
		}
		return false;
	}

	public static DataFlavor getFirstMatchingFlavor(DropTargetDragEvent e,
			DataFlavor[] acceptableFlavors) {
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
}
