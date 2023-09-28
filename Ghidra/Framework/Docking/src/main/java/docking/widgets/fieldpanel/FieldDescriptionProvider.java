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
package docking.widgets.fieldpanel;

import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;

/**
 * Provides descriptions for fields in a field panel
 */
public interface FieldDescriptionProvider {

	/**
	 * Gets a description for the given location and field.
	 * @param loc the FieldLocation to get a description for
	 * @param field the Field to get a description for 
	 * @return a String describing the given field location
	 */
	public String getDescription(FieldLocation loc, Field field);
}
