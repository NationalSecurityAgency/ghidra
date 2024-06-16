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
package ghidra.framework.options;

import java.beans.PropertyChangeListener;
import java.util.HashMap;

public class EditorStateFactory {

	HashMap<String, EditorState> cache = new HashMap<String, EditorState>();

	public EditorStateFactory() {
	}

	public EditorState getEditorState(Options options, String name,
			PropertyChangeListener listener) {

		String optionID = options.getID(name);
		EditorState editorState = cache.get(optionID);
		if (editorState == null) {
			editorState = new EditorState(options, name);
			cache.put(optionID, editorState);
		}

		editorState.addListener(listener); // this class uses a set to avoid duplicate listeners
		return editorState;
	}

	public void clear(Options options, String name) {
		cache.remove(options.getID(name));
	}

	public void clearAll() {
		cache.clear();
	}
}
