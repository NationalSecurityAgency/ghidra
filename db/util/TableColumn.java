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
package db.util;

import db.Field;

public class TableColumn {

	private final Class<? extends Field> columnClass;
	private boolean indexed;
	
	private int ordinal;
	private String name;
	
	public TableColumn( Class<? extends Field> columnClass ) {
		this( columnClass, false );
	}
	
	public TableColumn( Class<? extends Field> columnClass, boolean isIndexed ) {
		this.columnClass = columnClass;
		indexed = isIndexed;
	}

	void setName( String name ) {
		this.name = name;		
	}
	
	void setOrdinal( int ordinal ) {
		this.ordinal = ordinal;
	}
	
	public boolean isIndexed() {
		return indexed;
	}
	
	public Class<? extends Field> getColumnClass() {
		return columnClass;
	}

	public String name() {
		return name;
	}

	public int column() {
		return ordinal;
	}

	@Override
	public String toString() {
		return name() + "("+ ordinal +")";
	}
}
