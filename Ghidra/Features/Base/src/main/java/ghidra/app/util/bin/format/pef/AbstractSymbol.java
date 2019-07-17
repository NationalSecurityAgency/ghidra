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
package ghidra.app.util.bin.format.pef;

import ghidra.app.util.bin.StructConverter;

abstract class AbstractSymbol implements StructConverter {

	/** Weak symbol mask*/
	public final static int kPEFWeakImportSymMask = 0x80;

	/**
	 * Returns the symbol's name.
	 * @return the symbol's name
	 */
	public abstract String getName();
	/**
	 * Returns the symbol's class.
	 * @return the symbol's class
	 */
	public abstract SymbolClass getSymbolClass();

	@Override
	public String toString() {
		return getName()+" "+getSymbolClass();
	}
}
