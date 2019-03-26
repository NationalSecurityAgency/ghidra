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
package ghidra.app.plugin.core.programtree;

import ghidra.app.cmd.module.ReorderModuleCmd;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.DuplicateGroupException;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.listing.Group;
import ghidra.program.model.listing.ProgramModule;
import ghidra.util.Msg;
import ghidra.util.exception.NotFoundException;

import java.awt.dnd.DnDConstants;

import javax.swing.SwingUtilities;
import javax.swing.tree.TreePath;

/**
 * Manage the drop operation for reordering modules and fragments.
 */
class ReorderManager {

    private ProgramDnDTree tree;

    ReorderManager(ProgramDnDTree tree) {
        this.tree = tree;
    }

    /**
     * Return true if the destNode can accept the dropNode.
     */
    boolean isDropSiteOk(ProgramNode destNode, ProgramNode dropNode,
                                int dropAction, int relativeMousePos) {

        ProgramModule mParent = destNode.getParentModule();
        Group dragGroup = dropNode.getGroup();

        if (dragGroup.equals(destNode.getGroup())) {
            return false; // can't drop a group onto itself
        }
		if (mParent == null && relativeMousePos != 0) {
			return false;// can't reorder above or below root
		}
        // if the target node is the same as the parent of the
        // fromObject (node to be dropped), then the action
        // must be a move, because this is just a reorder of the
        // children.
        if (destNode.equals(dropNode.getParent())) {
            if (dropAction != DnDConstants.ACTION_MOVE) {
                return false;
            }
            return true;
        }
        if (dropNode.getParent().equals(destNode.getParent()) &&
            dropAction != DnDConstants.ACTION_MOVE) {
            return false;
        }
        if (!dropNode.getParent().equals(destNode.getParent())) {
            // if parent nodes are different, check to make sure this
            // fragment does not already exist as a child of the
            // parent of the fromObject
            if (dropNode.isFragment() ) {

                ProgramFragment frag = dropNode.getFragment();

                if (mParent != null &&
                    mParent.contains(frag)) {
                    return false;
                }
                // this is the root; make sure fragment does not
                // already exist as a child of root...
                if (mParent == null && 
                    destNode.getModule().contains(frag)) {
                    return false;
                }

                if (destNode.isModule()) {
                    ProgramModule dm = destNode.getModule();
                    if (dm.contains(frag)) {
                        return false;
                    }
                }
                return true;
            }

            // fromObject must be a module...
            ProgramModule m = dropNode.getModule();

            if (mParent != null && (!m.equals(mParent) &&
                                    mParent.contains(m)) || m.equals(mParent) ) {
                return false;
            }
            // this is the root; make sure module does not
            // already exist as a child of root...
            if (mParent == null && 
                destNode.getModule().contains(m) ) {
                return false;
            }
        }
        //else parent nodes are the same, so this a reorder

        if (destNode.isModule() && dropAction == DnDConstants.ACTION_COPY) {
            ProgramModule dm = destNode.getModule();
            if (dropNode.isModule()) {
                if (dm.contains(dropNode.getModule())) {
                    return false;
                }
            }
            else {
                if (dm.contains(dropNode.getFragment())) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Add the given data to the destination node.
     * @param destNode destination node for the data.
     * @param dropNode data to add
     */
    void add(ProgramNode destNode, ProgramNode[] dropNodes, int dropAction, int relativeMousePos) 
            throws NotFoundException, CircularDependencyException, DuplicateGroupException {

        ProgramModule targetModule = destNode.getModule();
        ProgramFragment targetFrag = destNode.getFragment();
        if (targetModule == null && targetFrag == null) {
            tree.clearDragData();
            return; // ignore the drop
        }

		int transactionID = tree.startTransaction("Reorder");
		if (transactionID < 0) {
			return;
		}

		try {
            for ( int i = 0; i < dropNodes.length; i++ ) {
                ProgramNode parentNode = (ProgramNode)destNode.getParent();
                reorderNode( destNode, dropAction, relativeMousePos, parentNode, dropNodes[i] );
            }
		} finally {
			tree.endTransaction(transactionID, true);
		}			
    }

    private void reorderNode( ProgramNode destNode, int dropAction,
            int relativeMousePos, ProgramNode parentNode, ProgramNode dropNode )
            throws NotFoundException, CircularDependencyException, DuplicateGroupException {
                
        if (!reorderChildren(destNode, dropNode, relativeMousePos)) {
            int index;
            
        	// this is the case where destNode and dropNode have different parents...        
        	if (relativeMousePos < 0) {
        		if (parentNode == null) {
        			return;
        		}
        		index = parentNode.getIndex(destNode);	
        	}
        	else {
        		// if destNode is a module and if it is expanded,
        		// then dropNode will go inside the module
        		if (destNode.isModule() && tree.isExpanded(destNode.getTreePath())) {
        			index = 0;
        			destNode = (ProgramNode)destNode.getChildAt(0);
        		}
        		else {
        			// destNode is a module or a fragment, but place
        			// destNode after it
        			index = parentNode.getIndex(destNode);
        			++index;
        		} 
        			
        	}
        	addGroup(destNode, dropNode, index, dropAction);
        	ProgramNode child = (ProgramNode)parentNode.getChildAt(index);
        	selectNode(dropNode, child);
        }
    }

	/**
	 * Reorder children with the same module.
	 * @return true if reordering was done; false if no changes
	 * were made
	 */
	private boolean reorderChildren(ProgramNode destNode, ProgramNode dropNode,  
			int relativeMousePos)  {

		boolean didReorder = false;
		
		int index = 0;
		ProgramNode parentNode = (ProgramNode)destNode.getParent();
		ProgramModule dropParentModule = dropNode.getParentModule();
		ProgramModule targetModule = destNode.getModule();
			
		if (parentNode.equals(dropNode.getParent())) {
			didReorder = true;
        	targetModule = parentNode.getModule();
			int myIndex = parentNode.getIndex(dropNode);

        	index = parentNode.getIndex(destNode);
			if (relativeMousePos < 0 && myIndex < index) {
				--index;
			}
			else if (relativeMousePos > 0 && myIndex > index) {
				++index;
			}
			Group group = dropNode.getGroup();
			ReorderModuleCmd cmd = new ReorderModuleCmd(tree.getTreeName(),
					targetModule.getName(),
					group.getName(), index);

			if (tree.getTool().execute(cmd, tree.getProgram())) {
            	tree.reorder(group, dropParentModule, index);
				ProgramNode child = (ProgramNode)parentNode.getChildAt(index);
				addToSelection(child);
			}	        	
			else {
				Msg.showError(this, tree, "Error Moving Child", cmd.getStatusMsg());
			}
		}
		return didReorder;
	}
    ////////////////////////////////////////////////////////////////////
    
    /**
     * Match the expansion state for the dropNode and the nodeToSelect
     * (which is the new node that just got added). Select the new
     * node.
     */
    private void selectNode(ProgramNode dropNode, ProgramNode nodeToSelect) {
    	
        // apply expansion state of the dropped node to the new node.
        tree.matchExpansionState(dropNode, nodeToSelect);

        // add the target node to the selection later so
        // that the selection shows as being selected; 
        // without the invokeLater(), the path is not
        // rendered as being selected.
		addToSelection(nodeToSelect);
    }

	/**
	 * Add the path for the given node to the selection.
	 */
	private void addToSelection(ProgramNode node) {
		final TreePath p = node.getTreePath();
		tree.addSelectionPath(p);
		Runnable r = new Runnable() {
		    public void run() {
		        tree.addSelectionPath(p);
		    }
		};
		SwingUtilities.invokeLater(r);
	}
    
    /**
     * Add a new group to the destNode or re-parent the drop Node to
     * the destNode's parent (or to root if destNode's parent is null).
     * @param destNode drop site for dropped node
     * @param dropNode node to drop at destNode
     * @param targetIndex new index for node that is added
     * @param dropAction DnDConstants.ACTION_COPY or ACTION_MOVE
     */
    private void addGroup(ProgramNode destNode, ProgramNode dropNode,
                      int targetIndex, int dropAction) 
        throws NotFoundException, CircularDependencyException,
                DuplicateGroupException{
        Group group = null;
        ProgramNode targetParent = (ProgramNode)destNode.getParent();
        
        // first add drop fragment or module
        //  to target's parent
        ProgramModule targetParentModule = 
            (targetParent != null) ? targetParent.getModule() :
                                            destNode.getModule();

        ProgramFragment dropFragment = dropNode.getFragment();
        ProgramModule dropModule = dropNode.getModule();

        if (dropAction == DnDConstants.ACTION_COPY) {
            if (dropFragment!= null) {
                targetParentModule.add(dropFragment);
                group = dropFragment;
            }
            else {
                targetParentModule.add(dropModule);
                group = dropModule;
            }
        }
        else {
            targetParentModule.reparent(dropNode.getName(),
                                        dropNode.getParentModule());
            if (dropFragment != null) {
                group = dropFragment;
            }
            else {
                group = dropModule;
            }
        }
        tree.groupAdded(group);
        targetParentModule.moveChild(group.getName(),
                                 targetIndex);
        tree.reorder(dropNode.getGroup(), targetParentModule,
                             targetIndex);
    }
}
