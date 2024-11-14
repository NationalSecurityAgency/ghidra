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
package ghidra.app.util.bin.format.pdb2.pdbreader;

import org.apache.commons.lang3.StringUtils;

/**
 * Parser, extending {@link TypeProgramInterfaceParser}, for detecting and returning the
 *  appropriate {@link TypeProgramInterface} format to be used as the Item Program
 *  Interface for the filename given.
 */
public class ItemProgramInterfaceParser extends TypeProgramInterfaceParser {

	private static final int ITEM_PROGRAM_INTERFACE_STREAM_NUMBER = 4;

	/**
	 * Returns the standard stream number that contains the serialized Item Program Interface
	 * @return the standard stream number that contains the Item Program Interface
	 */
	@Override
	protected int getStreamNumber() {
		return ITEM_PROGRAM_INTERFACE_STREAM_NUMBER;
	}

	/**
	 * Returns the appropriate {@link RecordCategory} needed while processing
	 *  the Type Program Interface} (vs. Item Program Interface)
	 * @return {@link RecordCategory#ITEM}
	 */
	@Override
	protected RecordCategory getCategory() {
		return RecordCategory.ITEM;
	}

	/**
	 * Returns whether there is a reasonable error when searching for a version number.  For
	 *  the standard TPI case, any unrecognized version number is a reasonable error.  For this
	 *  IPI case, we have to be able to error on an unrecognized version number, so we report
	 *  true for version numbers that would seem reasonable.  We return false if the versionNumber
	 *  is not a reasonable number, which allows the "hack" to work for IPI where a failure to
	 *  parse an IPI is an indication that there is no IPI (which is first screened by the
	 *  {@link #hackCheckNoNameForStream(NameTable)} method
	 * @param versionNumber the versionNumber being checked
	 * @return {@code true} if the error is a reasonable error
	 */
	@Override
	protected boolean isReasonableError(int versionNumber) {
		String str = String.format("%d", versionNumber);
		return (str.length() == 8 &&
			(str.startsWith("199") || str.startsWith("200") || str.startsWith("201")));
	}

	/**
	 * Returns {@code true} if there is not a name in the name table assigned to the stream number
	 * for the IPI
	 * @param nameTable the name table that contains the stream/name map
	 * @return {@code true} if no name associated with the IPI stream number
	 */
	public static boolean hackCheckNoNameForStream(NameTable nameTable) {
		String name = nameTable.getNameFromStreamNumber(ITEM_PROGRAM_INTERFACE_STREAM_NUMBER);
		return StringUtils.isEmpty(name);
	}

}
