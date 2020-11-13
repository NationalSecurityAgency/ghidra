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
package docking.dnd;

import java.awt.datatransfer.DataFlavor;

/**
 * Generic data flavor class to override the equals(DataFlavor) method
 * in order to have data flavors support the same general class types
 * such as an ArrayList.
 */
public class GenericDataFlavor extends DataFlavor {

	/**
	 * Construct a new GenericDataFlavor.
	 */
	public GenericDataFlavor() {
		super();
	}

	/**
	 * Construct a GenericDataFlavor that represents a Java class 
	 * @param representationClass the class used to transfer data in this flavor
	 * @param humanPresentableName the human-readable string used to 
	 * identify this flavor. If this parameter is null then the value of 
	 * the the MIME Content Type is used.
	 */
	public GenericDataFlavor(Class<?> representationClass, String humanPresentableName) {
		super(representationClass, humanPresentableName);
	}

	/**
	 * construct a GenericDataFlavor from a Mime Type string.
	 * 
	 * @param mimeType he string used to identify the MIME type for this flavor
	 * The string must specify a "class="
	 *  parameter in order to succeed in constructing a DataFlavor.
	 * @exception ClassNotFoundException if the class could not be loaded
	 * @exception IllegalArgumentException thrown if mimeType does not
	 * specify a "class=" parameter 
	 */
	public GenericDataFlavor(String mimeType) throws ClassNotFoundException {
		super(mimeType);
	}

	/**
	 * Construct a GenericDataFlavor that represents a MimeType 
	 * If the mimeType is 
	 * {@code "application/x-java-serialized-object; class=<representation class>",
	 * the result is the same as calling 
	 * new GenericDataFlavor(Class:forName(<representation class>)}
	 * @param mimeType the string used to identify the MIME type for 
	 * this flavor
	 * @param humanPresentableName  the human-readable string used to 
	 * identify this flavor
	 * @exception IllegalArgumentException thrown if the mimeType does not 
	 * specify a "class=" parameter, or if the class is not
	 * successfully loaded
	 */
	public GenericDataFlavor(String mimeType, String humanPresentableName) {
		super(mimeType, humanPresentableName);
	}

	/**
	 * Construct a GenericDataFlavor that represents a MimeType 
	 * If the mimeType is 
	 * {@code "application/x-java-serialized-object; class=<representation class>",
	 * the result is the same as calling 
	 * new GenericDataFlavor(Class:forName(<representation class>).}
	 *
	 * @param mimeType the string used to identify the MIME type for this flavor
	 * @param humanPresentableName the human-readable string used to 
	 * identify this flavor. 
	 * @param classLoader class loader to load the class
	 * @exception ClassNotFoundException is thrown if class could not be loaded
	 */
	public GenericDataFlavor(String mimeType, String humanPresentableName, ClassLoader classLoader)
			throws ClassNotFoundException {
		super(mimeType, humanPresentableName, classLoader);
	}

	/**
	 * Return true if dataFlavor equals this generic data flavor.
	 */
	@Override
	public boolean equals(DataFlavor dataFlavor) {
		boolean isEqual = super.equals(dataFlavor);
		if (isEqual) {
			isEqual = getHumanPresentableName().equals(dataFlavor.getHumanPresentableName());
		}
		return isEqual;
	}

	/**
	 * Return true if obj is equal this generic data flavor.
	 */
	@Override
	public boolean equals(Object obj) {
		boolean isEqual = super.equals(obj);

		if (isEqual) {
			DataFlavor df = (DataFlavor) obj;
			isEqual = this.equals(df);
		}
		return isEqual;
	}

}
