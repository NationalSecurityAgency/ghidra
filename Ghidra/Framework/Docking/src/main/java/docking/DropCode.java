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

import java.awt.Cursor;

/**
 * An enum that represents available drag-n-drop options for a docking tool.  There are also
 * convenience methods for translating this drop code into a cursor and window position.
 */
enum DropCode {
	INVALID, STACK, LEFT, RIGHT, TOP, BOTTOM, ROOT, WINDOW;

	public Cursor getCursor() {
		Cursor c = HeaderCursor.NO_DROP;
		switch (this) {
			case LEFT:
				c = HeaderCursor.LEFT;
				break;
			case RIGHT:
				c = HeaderCursor.RIGHT;
				break;
			case TOP:
				c = HeaderCursor.TOP;
				break;
			case BOTTOM:
				c = HeaderCursor.BOTTOM;
				break;
			case STACK:
				c = HeaderCursor.STACK;
				break;
			case ROOT:
				c = HeaderCursor.STACK;
				break;
			case WINDOW:
				c = HeaderCursor.NEW_WINDOW;
				break;
			case INVALID:
				break;
		}

		return c;
	}

	public WindowPosition getWindowPosition() {
		switch (this) {
			case BOTTOM:
				return WindowPosition.BOTTOM;
			case LEFT:
				return WindowPosition.LEFT;
			case RIGHT:
				return WindowPosition.RIGHT;
			case STACK:
				return WindowPosition.STACK;
			case TOP:
				return WindowPosition.TOP;
			default:
				return WindowPosition.STACK;
		}
	}
}
