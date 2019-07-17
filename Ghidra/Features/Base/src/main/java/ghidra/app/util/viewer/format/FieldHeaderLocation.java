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
package ghidra.app.util.viewer.format;

import ghidra.app.util.viewer.field.FieldFactory;

/**
 * Class used to represent a location within the field header component.
 */

public class FieldHeaderLocation {
	private FieldFormatModel model;
	private FieldFactory factory;
	private int row;
	private int col;
	
	/**
	 * Construct a new FieldHeaderLocation
	 * @param model the model containing this location
	 * @param factory the factory the containing this location.
	 * @param row the row containing the factory in the header
	 * @param col the column containing the factory in the header.
	 */
	public FieldHeaderLocation(FieldFormatModel model, FieldFactory factory, int row, int col){
		this.model = model;
		this.factory = factory;
		this.row = row;
		this.col = col;
	}
	
	/**
	 * Returns the header row for this location.
	 */
	public int getRow() {
		return row;
	}
	
	/**
	 * Returns the header column for this location.
	 */
	public int getColumn() {
		return col;
	}
	
	/**
	 * Returns the FieldFormatModel for this location.
	 */
	public FieldFormatModel getModel() {
		return model;
	}
	
	/**
	 * Returns the field factory for this location.
	 */
	public FieldFactory getFieldFactory() {
		return factory;
	}
}
