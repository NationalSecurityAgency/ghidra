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
package docking.widgets.fieldpanel.listener;

/**
 * Listener interface for objects that are notified when a change is made to a Field, or Fields
 * were added or removed from a set of Fields.
 * 
 */
public interface FieldListener {
	/**
	 * Notifies the listener when the set of indexes changes - either the number
	 * of indexes or the fundamental data types associated with thos indexes.
	 */
	void indexSetChanged();

	/**
	 * Notifies the listener the data in the models has changed within the given
	 * index range.
	 * @param min the minimum index affected by the data change.
	 * @param max the maximum index affected by the data change.
	 */
	void dataChanged(int min,int max);

	/**
	 * Notifies the listener that the width of this field has changed.
	 * @param width the new widht of the field.
	 */
	void widthChanged(int width);
}
