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
package docking;

import ghidra.util.datastruct.FixedSizeStack;

import javax.swing.undo.UndoableEdit;

public class UndoRedoKeeper {

	private static final int MAX_UNDO_REDO_SIZE = 50;

	private FixedSizeStack<UndoableEdit> undoStack = new FixedSizeStack<UndoableEdit>(
		MAX_UNDO_REDO_SIZE);
	private FixedSizeStack<UndoableEdit> redoStack = new FixedSizeStack<UndoableEdit>(
		MAX_UNDO_REDO_SIZE);

	void addUndo(UndoableEdit edit) {
		undoStack.push(edit);
		redoStack.clear();
	}

	void undo() {
		if (undoStack.isEmpty()) {
			return;
		}
		UndoableEdit item = undoStack.pop();
		redoStack.push(item);
		item.undo();
	}

	void redo() {
		if (redoStack.isEmpty()) {
			return;
		}

		UndoableEdit item = redoStack.pop();
		undoStack.push(item);
		item.redo();
	}

	public void clear() {
		undoStack.clear();
		redoStack.clear();
	}
}
