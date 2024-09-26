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
package ghidra.feature.vt.gui.duallisting;

import static ghidra.util.datastruct.Duo.Side.*;

import java.awt.Point;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.dnd.*;
import java.util.ArrayList;

import docking.dnd.*;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.markuptype.VTMarkupType;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.task.ApplyMarkupAtDestinationAddressTask;
import ghidra.features.base.codecompare.listing.ListingCodeComparisonPanel;
import ghidra.program.model.address.Address;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.Duo;

public class VTDualListingDragNDropHandler implements Draggable, Droppable {

	private Duo<ListingPanel> listingPanels;

	private VTController controller;
	ListingCodeComparisonPanel dualListingPanel;

	// Drag-N-Drop
	private DragSource dragSource;
	private DragGestureAdapter dragGestureAdapter;
	private DragSrcAdapter dragSourceAdapter;
	private int dragAction = DnDConstants.ACTION_MOVE;
	private DropTarget dropTarget;
	private DropTgtAdapter dropTargetAdapter;
	private DataFlavor[] acceptableFlavors; // data flavors that are valid.

	public VTDualListingDragNDropHandler(VTController controller,
			ListingCodeComparisonPanel dualListingPanel) {
		this.controller = controller;
		this.dualListingPanel = dualListingPanel;
		ListingPanel leftPanel = dualListingPanel.getListingPanel(LEFT);
		ListingPanel rightPanel = dualListingPanel.getListingPanel(RIGHT);
		listingPanels = new Duo<>(leftPanel, rightPanel);
		setUpDragDrop();
	}

	private void setUpDragDrop() {

		setUpDrop();

		// set up the component area as a drag site that provides mark-up items.
		dragSource = DragSource.getDefaultDragSource();
		dragGestureAdapter = new DragGestureAdapter(this);
		dragSourceAdapter = new DragSrcAdapter(this);
		dragSource.createDefaultDragGestureRecognizer(listingPanels.get(LEFT).getFieldPanel(),
			dragAction, dragGestureAdapter);
	}

	private void setUpDrop() {

		setAcceptableFlavors();

		// set up the destination fieldPanel as a drop target that accepts mark-up items.
		dropTargetAdapter =
			new DropTgtAdapter(this, DnDConstants.ACTION_COPY_OR_MOVE, acceptableFlavors);
		dropTarget = new DropTarget(listingPanels.get(RIGHT).getFieldPanel(),
			DnDConstants.ACTION_COPY_OR_MOVE, dropTargetAdapter, true);
		dropTarget.setActive(true);
	}

	private void setAcceptableFlavors() {
		acceptableFlavors = new DataFlavor[] { VTMarkupItemTransferable.localMarkupItemFlavor };
	}

	@Override
	public int getDragAction() {
		return dragAction;
	}

	@Override
	public DragSourceListener getDragSourceListener() {
		return dragSourceAdapter;
	}

	@Override
	public boolean isStartDragOk(DragGestureEvent e) {
		if (!listingPanels.get(LEFT).isStartDragOk()) {
			return false;
		}
		Point p = e.getDragOrigin();
		ProgramLocation programLocation = listingPanels.get(LEFT).getProgramLocation(p);
		VTMarkupItem markupItem =
			controller.getCurrentMarkupForLocation(programLocation,
				dualListingPanel.getProgram(LEFT));
		if (markupItem == null) {
			return false;
		}

		if (markupItem.canApply()) {
			return true;
		}

		VTMarkupItemDestinationAddressEditStatus status =
			markupItem.getDestinationAddressEditStatus();
		return status == VTMarkupItemDestinationAddressEditStatus.EDITABLE;
	}

	@Override
	public Transferable getTransferable(Point p) {
		if (!listingPanels.get(LEFT).contains(p)) {
			return null;
		}

		ProgramLocation programLocation = listingPanels.get(LEFT).getProgramLocation(p);
		VTMarkupItem markupItem = controller.getCurrentMarkupForLocation(programLocation,
			dualListingPanel.getProgram(LEFT));
		if (markupItem == null) {
			return null;
		}
		return new VTMarkupItemTransferable(markupItem);
	}

	@Override
	public boolean isDropOk(DropTargetDragEvent e) {
		return true;
	}

	@Override
	public void add(Object obj, DropTargetDropEvent event, DataFlavor f) {
		VTMarkupItem markupItem = (VTMarkupItem) obj;
		VTMarkupType markupType = markupItem.getMarkupType();
		Point p = event.getLocation();
		ProgramLocation loc = listingPanels.get(RIGHT).getProgramLocation(p);

		Address newDestinationAddress =
			markupType.getAddress(loc, dualListingPanel.getProgram(RIGHT));
		if (newDestinationAddress == null) {
			Msg.showInfo(getClass(), dualListingPanel, "Invalid Drop Location",
				markupType.getDisplayName() + " was not dropped at a valid location.");
			return;
		}
		if ((markupItem.getStatus() == VTMarkupItemStatus.SAME) &&
			(SystemUtilities.isEqual(markupItem.getDestinationAddress(), newDestinationAddress))) {
			// Dropped at expected address and already the same there.
			Msg.showInfo(getClass(), dualListingPanel, "Already The Same", markupType
					.getDisplayName() +
				" was dropped at its expected\ndestination where the value is already the same.");
			return;
		}

		ArrayList<VTMarkupItem> arrayList = new ArrayList<VTMarkupItem>();
		arrayList.add(markupItem);

		// Use the following if you want to set the address and apply the markup item using the default action.
		ApplyMarkupAtDestinationAddressTask task = new ApplyMarkupAtDestinationAddressTask(
			controller.getSession(), arrayList, newDestinationAddress, controller.getOptions());

		controller.runVTTask(task);
	}
}
