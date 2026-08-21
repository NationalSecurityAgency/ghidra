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
package ghidra.app.decompiler;

import ghidra.program.model.address.Address;
import ghidra.program.util.ProgramLocation;

/**
 * Represents a location in the Decompiler.  This interface allows the Decompiler to subclass more
 * general {@link ProgramLocation}s while adding more detailed Decompiler information.
 */
public interface DecompilerLocation {

	public Address getFunctionEntryPoint();

	/**
	 * Results from the decompilation
	 * 
	 * @return C-AST, DFG, and CFG object. null if there are no results attached to this location
	 */
	public DecompileResults getDecompile();

	/**
	 * C text token at the current cursor location
	 * 
	 * @return token at this location, could be null if there are no decompiler results
	 */
	public ClangToken getToken();

	/**
	 * {@return the name of the token for the current location}
	 */
	public String getTokenName();

	/**
	 * {@return the line number}
	 */
	public int getLineNumber();

	/**
	 * {@return the character position}
	 */
	public int getCharPos();
}
