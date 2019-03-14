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
package docking.widgets.fieldpanel.internal;

import java.awt.Color;
import java.util.ArrayList;
import java.util.List;

import docking.widgets.fieldpanel.support.Highlight;


public class EmptyFieldBackgroundColorManager implements FieldBackgroundColorManager {
	public static final FieldBackgroundColorManager EMPTY_INSTANCE = new EmptyFieldBackgroundColorManager();
	public static final List<Highlight> EMPTY_HIGHLIGHT_LIST = new ArrayList<Highlight>();

	private EmptyFieldBackgroundColorManager() {
	}

	public List<Highlight> getSelectionHighlights(int row) {
		return EMPTY_HIGHLIGHT_LIST;
	}

	public Color getBackgroundColor() {
		return null;
	}

	public Color getPaddingColor(int padIndex) {
		return null;
	}
}
