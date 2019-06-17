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
package ghidra.pdb.pdbreader;

/**
 * Parser, extending {@link TypeProgramInterfaceParser}, for detecting and returning the
 *  appropriate {@link AbstractTypeProgramInterface} format to be used as the Item Program
 *  Interface for the filename given.
 */
public class ItemProgramInterfaceParser extends TypeProgramInterfaceParser {

	private static final int ITEM_PROGRAM_INTERFACE_STREAM_NUMBER = 4;

	/**
	 * Returns the standard stream number that contains the serialized Item Program Interface.
	 * @return The standard stream number that contains the Item Program Interface.
	 */
	@Override
	protected int getStreamNumber() {
		return ITEM_PROGRAM_INTERFACE_STREAM_NUMBER;

	}

	/**
	 * Returns the appropriate {@link CategoryIndex.Category} value needed for while processing
	 *  the Item Program Interface} (vs. Type Program Interface).
	 * @return {@link CategoryIndex.Category#ITEM}.
	 */
	@Override
	protected CategoryIndex.Category getCategory() {
		return CategoryIndex.Category.ITEM;

	}

}
