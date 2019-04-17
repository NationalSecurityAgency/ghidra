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
package ghidra.framework.task.gui;

import javax.swing.AbstractListModel;

public abstract class GTaskListModel<T> extends AbstractListModel<T> {
	protected void fireContentsChanged(int index0, int index1) {
		fireContentsChanged(this, index0, index1);
	}

	protected void fireIntervalAdded(int index0, int index1) {
		fireIntervalAdded(this, index0, index1);
	}

	protected void fireIntervalRemoved(int index0, int index1) {
		fireIntervalRemoved(this, index0, index1);
	}

}
