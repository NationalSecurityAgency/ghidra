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
package docking.widgets.tree.support;

import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.dnd.DnDConstants;
import java.util.List;

import docking.widgets.tree.GTreeNode;

public interface GTreeDragNDropHandler extends GTreeTransferHandler {
	/**
     * Return true if the dragUserData can be dragged.
     * @param dragUserData data where user is initiating the drag operation
     * @param dragAction user action for the drag operation
     */
    public boolean isStartDragOk(List<GTreeNode> dragUserData, int dragAction);
    /**
	 * Returns the supported Drag actions for this tree.  For available actions see
	 * {@link DnDConstants}.
	 * @return the supported Drag actions.
	 */
	public int getSupportedDragActions();


    /**
     * Return true if the drop site is valid for the given target.
     * @param destUserData destination for node being dragged
     * @param flavors flavor(s) being dragged
     * @param dropAction user action for drop operation
     */
    boolean isDropSiteOk(GTreeNode destUserData, DataFlavor[] flavors, int dropAction);

    /**
     * Add the given transferable's data to the destination user data.
     * @param destUserData destination node for the data.
     * @param transferable  the transferable being dragged whose data will be dropped.
     * @param dropAction user action for drop operation
     */
    void drop(GTreeNode destUserData, Transferable transferable, int dropAction);

}
