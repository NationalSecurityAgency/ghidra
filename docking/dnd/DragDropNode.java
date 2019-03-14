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

import javax.swing.Icon;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreePath;

/**
 * Defines a node that is in the DragDropTree.
 */
public abstract class DragDropNode extends DefaultMutableTreeNode {

    protected TreePath treePath;
    protected String name;

    /**
     * Constructs a new DragDropNode with the given name.
     * @param name the name to associate with this node.
     */
    public DragDropNode(String name) {
        super(name);
        this.name = name;
    }

    /**
     * Get the appropriate icon for this node's state; called
     * by the tree cell renderer.
     * @param expanded true if the node is expanded
     * @param leaf true if the node is a leaf node
     */
    public abstract Icon getIcon(boolean expanded, boolean leaf);

    /**
     * Return true if this node can be a drop target.
     * @param dropNode node being dragged and dropped;
     * could be null if the drag was initiated outside of the tree
     * @param dropAction DnDConstants value for copy or move
     */
    public abstract boolean isDropAllowed(DragDropNode dropNode, int dropAction); 

    /**
     * Get the tool tip for this node.
     */
    public String getToolTipText() {
        return null;
    }
    /**
     * Get the tree path for this node.
     * 
     * @return TreePath
     */
    public TreePath getTreePath() {
        if (treePath == null) {
            treePath = new TreePath(getPath());
        }
        return treePath;
    }

    /**
     * Set the name for this node.
     * @param name the name to set on this node.
     */
    public void setName(String name) {

        this.name = name;
        setUserObject(name);
    }
    /**
     * Get the name of this node.
     */
    public String getName() {
        return name;
    }
}
