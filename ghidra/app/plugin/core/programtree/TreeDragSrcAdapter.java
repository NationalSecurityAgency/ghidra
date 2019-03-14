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
package ghidra.app.plugin.core.programtree;


import java.awt.*;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DragSource;

import javax.swing.ImageIcon;

import docking.dnd.DragSrcAdapter;
import docking.dnd.Draggable;

import resources.ResourceManager;


/**
 * Drag source adapter on tree to set the custom cursors for the drag under
 * feedback.
 */
class TreeDragSrcAdapter extends DragSrcAdapter {
	
    private static String MOVE_CURSOR_FILENAME = "images/dragMoveCursor.gif";
    private static String COPY_CURSOR_FILENAME = "images/dragCopyCursor.gif";
    
    private static String MOVE_NAME = "MoveCursor";
    private static String COPY_NAME = "CopyCursor";
    
	private Cursor feedbackCursor;
	private Cursor copyCursor;
    private Cursor moveCursor;
	
	public TreeDragSrcAdapter(Draggable dragComponent) {
		super(dragComponent);
	}
	
	/**
	 * @see docking.dnd.DragSrcAdapter#getDropOkCursor(int)
	 */
	@Override
    protected Cursor getDropOkCursor(int action) {
		if (feedbackCursor != null) {
			return feedbackCursor;
		}
		return super.getDropOkCursor(action);
	}
	
	/**
	 * Get the appropriate cursor for the action and mouse position within the node.
	 * @param action move, copy, link
	 * @param relativeMousePos relative mouse position within the node:  -1 for inserting 
	 *        above the node, 0 for being at the node, 1 for inserting below the node
	 * @return cursor that is appropriate for the given action and relative mouse position
	 */
	Cursor getCursor(int action, int relativeMousePos) {
		Cursor c = null;
		if ((action & DnDConstants.ACTION_LINK) == DnDConstants.ACTION_LINK) {
			return super.getDropOkCursor(action);
		}
		if ((action & DnDConstants.ACTION_MOVE) == DnDConstants.ACTION_MOVE) {
			c = DragSource.DefaultMoveDrop;
			if (relativeMousePos != 0) {
				c = getMoveCursor();
			}
		}
		else {
		    c = DragSource.DefaultCopyDrop;
		    if (relativeMousePos != 0) {
		    	c = getCopyCursor();
		    }
		}
		return c;	
	}
		
	/**
	 * Set the cursor for drag under feedback.
	 * @param c cursor for feedback; may be null if there is no feedback.
	 */
	void setFeedbackCursor(Cursor c) {
		feedbackCursor = c;
	}
	
	private Cursor getMoveCursor() {
        if ( moveCursor == null ) {
            moveCursor = createCursor(MOVE_CURSOR_FILENAME, MOVE_NAME, new Point(0, 16));
        }
        return moveCursor;
    }

    private Cursor getCopyCursor() {
        if ( copyCursor == null ) {
            copyCursor = createCursor(COPY_CURSOR_FILENAME, COPY_NAME, new Point(0, 24));
        }
        return copyCursor;
    }
	
	/**
	 * Create a cursor with the filename and cursor name.
	 * @param filename a name from the images resource
	 * @param cursorName name to use int the createCustomCursor()
	 * method on Toolkit
	 */
	private static Cursor createCursor(String filename, String cursorName,
		Point hotSpot) {
		ImageIcon icon = ResourceManager.loadImage(filename);
		Image image = icon.getImage();
		Toolkit tk = Toolkit.getDefaultToolkit();
		Cursor cursor = tk.createCustomCursor(image, hotSpot, cursorName);
		return cursor;
	}

}
