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
package ghidra.app.util.demangler;

/**
 * A simple class to contain the various settings for demangling
 */
public class DemanglerOptions {

	private boolean applySignature = true;
	private boolean doDisassembly = true;
	private boolean demangleOnlyKnownPatterns = true;

	public DemanglerOptions() {
		// use default values
	}

	public DemanglerOptions(DemanglerOptions copy) {
		this.applySignature = copy.applySignature;
		this.doDisassembly = copy.doDisassembly;
		this.demangleOnlyKnownPatterns = copy.demangleOnlyKnownPatterns;
	}

	/**
	 * Checks if the apply signature option is currently set
	 *
	 * @return true if set to apply function signatures that are demangled
	 */
	public boolean applySignature() {
		return applySignature;
	}

	/**
	 * Set the option to apply function signatures that are demangled
	 *
	 * @param applySignature true to apply function signatures that are demangled
	 */
	public void setApplySignature(boolean applySignature) {
		this.applySignature = applySignature;
	}

	/**
	 * Checks if the option to perform disassembly for known data structures (like functions) when
	 * demangling is set
	 *
	 * @return true if the option is set
	 */
	public boolean doDisassembly() {
		return doDisassembly;
	}

	/**
	 * Sets the option to perform disassembly for known data structures (like functions) when
	 * demangling
	 *
	 * @param doDisassembly true to perform disassembly when demangling
	 */
	public void setDoDisassembly(boolean doDisassembly) {
		this.doDisassembly = doDisassembly;
	}

	/**
	 * Checks if the option to only demangle known mangled patterns is set
	 *
	 * @return true if only known mangled patterns will be demangled
	 */
	public boolean demangleOnlyKnownPatterns() {
		return demangleOnlyKnownPatterns;
	}

	/**
	 * Sets the option to only demangle known mangled patterns. Setting this to false causes
	 * most symbols to be demangled, which may result in some symbols getting demangled that were
	 * not actually mangled symbols.
	 *
	 * <P>Generally, a demangler will report an error if a symbol fails to demangle.   Hence,
	 * clients can use this flag to prevent such errors, signalling to the demangler to only
	 * attempt those symbols that have a known start pattern.  If the known start pattern list
	 * becomes comprehensive, then this flag can go away.
	 *
	 * @param demangleOnlyKnownPatterns true to only demangle known mangled patterns
	 */
	public void setDemangleOnlyKnownPatterns(boolean demangleOnlyKnownPatterns) {
		this.demangleOnlyKnownPatterns = demangleOnlyKnownPatterns;
	}

	@Override
	public String toString() {
		//@formatter:off
		return "{\n" +
			"\tdoDisassembly: " + doDisassembly + ",\n" +
			"\tapplySignature: " + applySignature + ",\n" +
			"\tdemangleOnlyKnownPatterns: " + demangleOnlyKnownPatterns + ",\n" +
		"}";
		//@formatter:on
	}
}
