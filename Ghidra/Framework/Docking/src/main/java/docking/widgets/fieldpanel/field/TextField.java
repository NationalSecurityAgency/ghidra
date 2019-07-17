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
package docking.widgets.fieldpanel.field;

import docking.widgets.fieldpanel.support.RowColLocation;


public interface TextField extends Field {

	/**
	 * Sets this field to be primary such that its row is primary
	 */
	public void setPrimary(boolean b);
    
    /**
     * Translates a screen coordinate to a row and column in the data from the factory
     * @param screenRow the row in the displayed field text.
     * @param screenColumn the column in the displayed field text.
     * @return a RowColLocation containing the row and column within the data from the factory.
     */
    public RowColLocation screenToDataLocation(int screenRow, int screenColumn);
    
    /**
     * Translates a data row and column into a screen row and column.
     * @param dataRow row as defined by the factory
     * @param dataColumn the character offset into the dataRow
     * @return row and column in the screen coordinate system.
     */
    public RowColLocation dataToScreenLocation(int dataRow, int dataColumn);

    /**
     * Returns true if the field is not displaying all the text information
     */
	public boolean isClipped();
	
	/**
	 * Returns the FieldElement at the given screen location.
	 * @param screenRow the row on the screen
	 * @param screenColumn the column on the screen
	 * @return the FieldElement at the given screen location.
	 */
	public FieldElement getFieldElement(int screenRow, int screenColumn);
	
}
