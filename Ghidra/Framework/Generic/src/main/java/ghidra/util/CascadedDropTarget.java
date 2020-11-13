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
package ghidra.util;

import java.awt.Component;
import java.awt.dnd.*;

/**
 * Combines two drop targets and sends events to them in priority order.  If the first drop target
 * accepts the event, then the second drop target is not accessed. 
 * <p>
 * Either of the given drop targets can be an instance of CascadedDropTarget, effectively creating 
 * a tree structure of drop targets.
 */
public class CascadedDropTarget extends DropTarget {

	private DropTarget primaryDropTarget;
	private DropTarget secondaryDropTarget;
	private DropTarget activeDropTarget;

	public CascadedDropTarget(Component comp, DropTarget firstDropTarget, DropTarget secondDropTarget) {
		super(comp, null);
		
		if ( firstDropTarget == null || secondDropTarget == null) {
			throw new NullPointerException( "Drop targets may not be null" );
		}
		
		this.primaryDropTarget = firstDropTarget;
		this.secondaryDropTarget = secondDropTarget;
	}

	@Override
	public synchronized void drop(DropTargetDropEvent dtde) {

		clearAutoscroll();
		if (activeDropTarget == null) {
			dtde.rejectDrop();	// MAC OSX can drop even if we told it not to in the dragOver method
			return;
		}
		activeDropTarget.drop(dtde);
	}

	@Override
	public synchronized void dragEnter(DropTargetDragEvent dtde) {
		
		initializeAutoscrolling(dtde.getLocation());
		DropTargetDragEventWrapper eventWrapper = new DropTargetDragEventWrapper(dtde);
		primaryDropTarget.dragEnter(eventWrapper);
		activeDropTarget = primaryDropTarget;
		if (!eventWrapper.isAccepted()) {
			activeDropTarget = secondaryDropTarget;
			secondaryDropTarget.dragEnter(eventWrapper);
		}
		if (!eventWrapper.isAccepted()) {
			activeDropTarget = null;
		}
		eventWrapper.flush();
	}

	@Override
	public synchronized void dragOver(DropTargetDragEvent dtde) {
		updateAutoscroll(dtde.getLocation());

		if (activeDropTarget == null) {
			DropTargetDragEventWrapper eventWrapper = new DropTargetDragEventWrapper(dtde);
			primaryDropTarget.dragOver(eventWrapper);
			activeDropTarget = primaryDropTarget;
			if (!eventWrapper.isAccepted()) {
				activeDropTarget = secondaryDropTarget;
				secondaryDropTarget.dragOver(eventWrapper);
			}
			if (!eventWrapper.isAccepted()) {
				activeDropTarget = null;
			}
			eventWrapper.flush();
		} else 		{
			activeDropTarget.dragOver(dtde);
		}
	}

	@Override
	public synchronized void dropActionChanged(DropTargetDragEvent dtde) {
		updateAutoscroll(dtde.getLocation());
		
		if (activeDropTarget != null) {
			activeDropTarget.dropActionChanged(dtde);		
		}
	}

	@Override
	public synchronized void dragExit(DropTargetEvent dte) {
		clearAutoscroll();
		primaryDropTarget.dragExit(dte);
		secondaryDropTarget.dragExit(dte);
	}

	public DropTarget getPrimaryDropTarget() {
		return primaryDropTarget;
	}
	public DropTarget getSecondaryDropTarget() {
		return secondaryDropTarget;
	}

	/**
	 * Removes the given drop target from anywhere within the tree of CascadedDropTargets.  
	 * 
	 * If the given <code>dropTarget</code> is an immediate child of this CascadedDropTarget (CDT), then 
	 * the other child is returned.  Otherwise, a reference to this CDT will be returned with the 
	 * given <code>dropTarget</code> having been removed from one of this CDT's children.  This method 
	 * effectively removes the given <code>dropTarget</code> from the hierarchy and collapses the tree 
	 * structure as needed.
	 *   
	 * @param dropTarget The target to remove
	 * @return the new drop target reference
	 */
	public DropTarget removeDropTarget( DropTarget dropTarget ) {
		// is the child ours?
		if ( primaryDropTarget == dropTarget ) {
			return secondaryDropTarget;
		}
		else if ( secondaryDropTarget == dropTarget ) {
			return primaryDropTarget;
		}
		
		if ( primaryDropTarget instanceof CascadedDropTarget ) {
			CascadedDropTarget cascadedDropTarget = (CascadedDropTarget) primaryDropTarget;
			primaryDropTarget = cascadedDropTarget.removeDropTarget( dropTarget );
		}
		
		if ( secondaryDropTarget instanceof CascadedDropTarget ) {
			CascadedDropTarget cascadedDropTarget = (CascadedDropTarget) secondaryDropTarget;
			secondaryDropTarget = cascadedDropTarget.removeDropTarget( dropTarget );
		}
		
		return this;
	}
}
class DropTargetDragEventWrapper extends DropTargetDragEvent {
	private boolean isAccepted = false;
	private int dragOperation;
	private DropTargetDragEvent originalEvent;
	private boolean isRejected;
	
	public DropTargetDragEventWrapper(DropTargetDragEvent ev) {
		super(ev.getDropTargetContext(), ev.getLocation(), ev.getDropAction(), ev.getSourceActions());
		this.originalEvent = ev;
	}
	
	@Override
	public void acceptDrag(int dragOp) {
		isAccepted = true;
		this.dragOperation = dragOp;
	}
	@Override
	public void rejectDrag() {
		isRejected = true;
	}
	boolean isAccepted() {
		return isAccepted;
	}
	void flush() {
		if (isAccepted) {
			originalEvent.acceptDrag(dragOperation);
		}
		else if (isRejected){
			originalEvent.rejectDrag();
		}
	}
}
