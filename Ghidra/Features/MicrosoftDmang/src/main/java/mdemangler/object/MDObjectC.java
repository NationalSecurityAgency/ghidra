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
package mdemangler.object;

import mdemangler.MDException;
import mdemangler.MDMang;
import mdemangler.naming.MDFragmentName;

/**
 * This class represents a derivative of an <b><code>MDObject</code></b> which is a C object
 *  (vs. a C++ object).
 */
public class MDObjectC extends MDObject {
	protected MDFragmentName name;
	int conventionIndex;
	int numParameterBytes;

	private final String callingConvention[] =
		{ "__cdecl", "__stdcall", "__fastcall", "__vectorcall" };

	public MDObjectC(MDMang dmang) {
		super(dmang);
		conventionIndex = -1;
		numParameterBytes = 0;
		name = new MDFragmentName(dmang);
	}

	/**
	 * Returns the name
	 * @return the name
	 */
	public String getName() {
		if (name == null) {
			return null;
		}
		return name.getName();
	}

	/**
	 * Returns a calling convention string if the C object is determined to be a function with
	 * a specified convention
	 * @return the convention or {@code null} if not determined to be a function with convention
	 */
	public String getCallingConvention() {
		if (conventionIndex == -1) {
			return null;
		}
		return callingConvention[conventionIndex];
	}

	/**
	 * Returns the number of parameter bytes if the C object is determined to be a function with
	 * a specified convention
	 * @return the number of bytes; will always be zero for __cdecl
	 */
	public int getNumParameterBytes() {
		return numParameterBytes;
	}

	@Override
	public void insert(StringBuilder builder) {
		// We've come up with the demangling output for the function format ourselves.  This
		// format does not output anything for __cdecl (default) convention
		if (conventionIndex >= 1 && conventionIndex <= 3) {
			builder.append(callingConvention[conventionIndex]);
			builder.append(' ');
		}
		builder.append(name);
		if (conventionIndex >= 1 && conventionIndex <= 3) {
			builder.append(',');
			builder.append(numParameterBytes);
		}
	}

	/*
	 * Follow are C-style mangling scheme under 32-bit model; __vectorcall also valid for 64-bit
	 *      __cdecl: '_' prefix; no suffix; example "_name"
	 *    __stdcall: '_' prefix; "@<decimal_digits>" suffix; example "_name@12"
	 *   __fastcall: '@' prefix; "@<decimal_digits>" suffix; example "@name@12"
	 * __vectorcall: no prefix; "@@<decimal_digits>" suffix; example "name@@12"
	 */
	@Override
	protected void parseInternal() throws MDException {
		if (!dmang.isFunction()) {
			name.parse();
			return;
		}

		int index = dmang.getIndex();
		char c = dmang.peek();
		if (c == '@') {
			conventionIndex = 2;
			dmang.next();
		}
		else if (c == '_') {
			conventionIndex = 0; // will be 0 or 1
			dmang.next();
		}
		else {
			conventionIndex = 3;
		}
		name.parse(); // This strips a trailing '@' if it exists
		c = dmang.peek();
		if (c == '@') {
			if (conventionIndex != 3) {
				throw new MDException("Error parsing C Object calling convention");
			}
			dmang.next(); // skip the '@'
		}
		else if (conventionIndex == 0 &&
			dmang.getMangledSymbol().charAt(dmang.getIndex() - 1) == '@') {
			conventionIndex = 1;
		}

		if (dmang.getArchitectureSize() != 32 && conventionIndex != 3) {
			conventionIndex = -1;
			dmang.setIndex(index); // reset iterator back to original location
			name.parse();
			return;
		}

		if (conventionIndex != 0) {
			numParameterBytes = parseNumParameterBytes();
		}

	}

	private int parseNumParameterBytes() throws MDException {
		int loc = dmang.getIndex();
		String str = dmang.getMangledSymbol().substring(loc);
		dmang.setIndex(loc + dmang.getNumCharsRemaining());
		try {
			return Integer.parseInt(str);
		}
		catch (NumberFormatException e) {
			throw new MDException("Error parsing C Object calling convention");
		}
	}

}

/******************************************************************************/
/******************************************************************************/
