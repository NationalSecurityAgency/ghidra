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
package docking;

import javax.swing.JTextPane;
import javax.swing.undo.CompoundEdit;
import javax.swing.undo.UndoableEdit;

import ghidra.util.datastruct.FixedSizeStack;

/**
 * Handles tracking undo and redo events.   Clients may wish to hold on to this class in order
 * to clear the undo/redo queue.
 * 
 * <p><b><u>Style Edits</u></b><br>
 * {@link JTextPane}s allow for styles (color, bold, etc) to be applied to their text.  The
 * default undo/redo events may arrive singly, not in bulk.   Thus, when the user presses undo, 
 * each style change is undo, one at a time.   This is intuitive when the user controls the 
 * application of style.  However, when style is applied programmatically, it can be odd to 
 * see that the user-type text does not change, but just the coloring applied to that text.
 * <p>
 * To address this issue, this class takes the approach of combining all style edits into a 
 * single bulk edit.  Then, as the user presses undo, all style edits can be removed together, as
 * well as any neighboring text edits.   <b>Put simply, this class tracks style edits such 
 * that an undo operation will undo all style changes, as well as a single text edit.</b>
 */
public class UndoRedoKeeper {

	private static final int MAX_UNDO_REDO_SIZE = 50;
	private static final String STYLE_EDIT_KEY = "style";

	private FixedSizeStack<UndoableEdit> undoStack = new FixedSizeStack<>(MAX_UNDO_REDO_SIZE);
	private FixedSizeStack<UndoableEdit> redoStack = new FixedSizeStack<>(MAX_UNDO_REDO_SIZE);

	private StyleCompoundEdit lastStyleUndo;

	void addUndo(UndoableEdit edit) {

		String name = edit.getPresentationName();
		if (name.contains(STYLE_EDIT_KEY)) {
			// (see header note about style edits)
			addStyleEdit(edit);
			return;
		}

		endOutstandingStyleEdits();

		undoStack.push(edit);
		redoStack.clear(); // new edit added; clear redo
	}

	private void endOutstandingStyleEdits() {
		if (lastStyleUndo != null) {
			lastStyleUndo.end();
			lastStyleUndo = null;
		}
	}

	private void addStyleEdit(UndoableEdit edit) {
		if (lastStyleUndo == null) {
			lastStyleUndo = new StyleCompoundEdit();
			undoStack.push(lastStyleUndo);
		}

		lastStyleUndo.addEdit(edit);
		redoStack.clear(); // new edit added; clear redo
	}

	void undo() {
		if (undoStack.isEmpty()) {
			return;
		}

		endOutstandingStyleEdits();

		UndoableEdit item = undoStack.pop();
		redoStack.push(item);
		item.undo();

		// (see header note)
		if (item instanceof StyleCompoundEdit) {
			undo(); // call again to get a 'real' edit
		}
	}

	void redo() {
		if (redoStack.isEmpty()) {
			return;
		}

		endOutstandingStyleEdits();

		UndoableEdit item = redoStack.pop();
		undoStack.push(item);
		item.redo();

		// (see header note)
		if (item instanceof StyleCompoundEdit) {
			undo(); // call again to get a 'real' edit
		}
	}

	public void clear() {
		undoStack.clear();
		redoStack.clear();
	}

	private static class StyleCompoundEdit extends CompoundEdit {
		// simple class for us to track internally
	}
}
