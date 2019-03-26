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

import java.awt.Point;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.dnd.DropTargetDragEvent;


/**
 * Interface used by the DragDropTree to know how to handle the
 * drag and drop operations.
 */
public interface DragDropManager {

    /**
     * Return true if the dragNode can be dragged.
     * @param dragNode node where user is initiating the drag operation
     * @param dragAction user action for the drag operation
     */
    public boolean isStartDragOk(DragDropNode dragNode, int dragAction);

    /**
     * Return true if the drop site is valid for the given target and drag event.
     * @param destNode destination for node being dragged
     * @param e the drag event
     * 
     */
    public boolean isDropSiteOk(DragDropNode destNode, DropTargetDragEvent e);

    /**
     * Add the given data to the destination node.
     * @param destNode destination node for the data.
     * @param data data to add
     * @param chosen data flavor for the data being added
     * @param dropAction user action for drop operation
     */
    public void add(DragDropNode destNode, Object data, 
                    DataFlavor chosen, int dropAction);

    /**
     * Remove the given sourceNodes. (It got moved, so remove it at the source)
     * @param sourceNodes nodes to remove. 
     */
    public void move(DragDropNode[] sourceNodes); 

    /**
     * Return the data flavors that can be dragged and dropped.
     */
    public DataFlavor[] getAcceptableFlavors();

    /**
     * Get the transferable at the given point.
     * @param p point where the mouse pointer is when the drag begins
     */
    public Transferable getTransferable(Point p);

}

