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
package ghidra.app.util.bin.format.pdb2.pdbreader.type;

import java.math.BigInteger;

import ghidra.app.util.bin.format.pdb2.pdbreader.IdMsParsable;
import ghidra.app.util.bin.format.pdb2.pdbreader.RecordNumber;

public interface MsType extends IdMsParsable {

	/**
	 * If the type has a name element, returns this name; else returns an empty String.
	 * @return Name of this type
	 */
	default String getName() {
		return "";
	}

	/**
	 * Returns the record number of this type.
	 * @return the record number.
	 */
	default RecordNumber getRecordNumber() {
		return RecordNumber.NO_TYPE;
	}

	/**
	 * Returns the size of the datatype.
	 * @return size of the datatype.
	 */
	default BigInteger getSize() {
		return BigInteger.ZERO;
	}

	/**
	 * Returns the size of the datatype.
	 * @return size of the datatype.
	 */
	default long getLength() {
		return getSize().longValueExact();
	}

}
