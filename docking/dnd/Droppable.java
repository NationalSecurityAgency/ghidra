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
import java.awt.dnd.DropTargetDragEvent;
import java.awt.dnd.DropTargetDropEvent;

/**
 * Methods called by the DropTargetAdapter that implements the DropTargetListener interface
 */
public interface Droppable {

	/**
	 * Return true if is OK to drop the transferable at the location specified the event
	 * @param e event that has current state of drag and drop operation 
	 * @return true if OK
	 */
	public boolean isDropOk(DropTargetDragEvent e);

	/**
	 * Set drag feedback according to the ok parameter
	 * @param ok true means the drop action is OK
	 * @param e event that has current state of drag and drop operation 
	 */
	public void dragUnderFeedback(boolean ok, DropTargetDragEvent e);

	/**
	 * Revert back to normal if any drag feedback was set
	 */
	public void undoDragUnderFeedback();

	/**
	 * Add the object to the droppable component. The DropTargetAdapter
	 * calls this method from its drop() method.
	 * 
	 * @param obj Transferable object that is to be dropped.
	 * @param e  has current state of drop operation
	 * @param f represents the opaque concept of a data format as 
	 * would appear on a clipboard, during drag and drop.
	 */
	public void add(Object obj, DropTargetDropEvent e, DataFlavor f);

}
