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
package ghidra.app.util;

import java.awt.datatransfer.DataFlavor;

/**
 * Defines a "type" for items in the Clipboard
 */
public class ClipboardType {

	private DataFlavor flavor;
	private String typeName;

	/**
	 * Constructs a new ClipboardType
	 * @param flavor the DataFlavor of the data in the clipboard
	 * @param typeName the name for this ClipboardType
	 */
	public ClipboardType(DataFlavor flavor, String typeName) {
		this.flavor = flavor;
		this.typeName = typeName;
	}

	/**
	 * Returns the DataFlavor for this type
	 * @return the flavor
	 */
	public DataFlavor getFlavor() {
		return flavor;
	}

	/**
	 * Returns the name of this type
	 * @return the name
	 */
	public String getTypeName() {
		return typeName;
	}

	@Override
	public String toString() {
		return typeName;
	}
}
