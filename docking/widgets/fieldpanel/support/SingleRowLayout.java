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
package docking.widgets.fieldpanel.support;

import docking.widgets.fieldpanel.field.Field;

/**
 *  Convienence class for SingleRowLayout.  It provides numerous constructors to
 *  make it easier to create RowLayouts.
 */

public class SingleRowLayout extends RowLayout {

	/**
	 * Construct a SingleRowLayout with a single field.
	 * @param field1 the single field in this layout
	 */
	public SingleRowLayout(Field field1) {
		super(new Field[] { field1 }, 0);
	}

	/**
	 * Construct a SingleRowLayout with two fields.
	 * @param field1 the first field in the layout.
	 * @param field2 the second field in the layout.
	 */
	public SingleRowLayout(Field field1, Field field2) {
		super(new Field[] { field1, field2 }, 0);
	}

	/**
	 * Construct a SingleRowLayout with three fields.
	 * @param field1 the first field in the layout.
	 * @param field2 the second field in the layout.
	 * @param field3 the third field in the layout.
	 */
	public SingleRowLayout(Field field1, Field field2, Field field3) {
		super(new Field[] { field1, field2, field3 }, 0);
	}

	/**
	 * Construct a SingleRowLayout with four fields.
	 * @param field1 the first field in the layout.
	 * @param field2 the second field in the layout.
	 * @param field3 the third field in the layout.
	 * @param field4 the fourth field in the layout,
	 */
	public SingleRowLayout(Field field1, Field field2, Field field3, Field field4) {
		super(new Field[] { field1, field2, field3, field4 }, 0);
	}

	/**
	 * Construct a SingleRowLayout with five fields.
	 * @param field1 the first field in the layout.
	 * @param field2 the second field in the layout.
	 * @param field3 the third field in the layout.
	 * @param field4 the fourth field in the layout.
	 * @param field5 the fifth field in the layout.
	 */
	public SingleRowLayout(Field field1, Field field2, Field field3, Field field4, Field field5) {
		super(new Field[] { field1, field2, field3, field4, field5 }, 0);
	}

	/**
	 * Construct a SingleRowLayout from a list of fields.
	 * @param fields an array of fields to put in this layout
	 * @param rowNum the row number of the layout within a multiRow layout.
	 */
	public SingleRowLayout(Field[] fields, int rowNum) {
		super(fields, rowNum);
	}

	/**
	 * Construct a SingleRowLayout from a list of fields.
	 * @param fields an array of fields to put in this layout
	 */
	public SingleRowLayout(Field[] fields) {
		super(fields, 0);
	}

	@Override
	public String toString() {
		StringBuffer buffy = new StringBuffer();
		int n = getNumFields();
		for (int i = 0; i < n; i++) {
			Field layoutField = getField(i);
			if (buffy.length() > 0) {
				buffy.append(", ");
			}
			buffy.append(layoutField.getText());
		}
		return buffy.toString();
	}
}
