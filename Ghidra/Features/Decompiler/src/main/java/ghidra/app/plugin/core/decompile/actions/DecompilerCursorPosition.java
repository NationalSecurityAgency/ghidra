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
package ghidra.app.plugin.core.decompile.actions;

import docking.widgets.CursorPosition;
import docking.widgets.fieldpanel.support.FieldLocation;

public class DecompilerCursorPosition extends CursorPosition {
	private FieldLocation location;

	DecompilerCursorPosition(FieldLocation location) {
		super(location.col);
		this.location = location;
	}

	FieldLocation getFieldLocation() {
		return location;
	}

	@Override
	public void setOffset(int offset) {
		location.col += offset;
	}
}
