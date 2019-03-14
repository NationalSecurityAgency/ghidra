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
 * A simple class to contain the various settings for demangling.
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
	 * True signals to apply function signatures that are demangled.
	 * 
	 * @param doSignature True signals to apply function signatures that are demangled. 
	 */
	public boolean applySignature() {
		return applySignature;
	}

	/**
	 * True signals to apply function signatures that are demangled.
	 * 
	 * @param doSignature True signals to apply function signatures that are demangled. 
	 */
	public void setApplySignature(boolean applySignature) {
		this.applySignature = applySignature;
	}

	/**
	 * True signals to perform disassembly for known data structures (like functions) when 
	 * demangling.
	 * 
	 * @param doSignature True signals to perform disassembly 
	 */
	public boolean doDisassembly() {
		return doDisassembly;
	}

	/**
	 * True signals to perform disassembly for known data structures (like functions) when 
	 * demangling.
	 * 
	 * @param doSignature True signals to perform disassembly 
	 */
	public void setDoDisassembly(boolean doDisassembly) {
		this.doDisassembly = doDisassembly;
	}

	/**
	 * True signals to only demangle symbol names that follow known mangled patterns.  False triggers
	 * all symbols to be demangled, which results in some symbols getting demangled that were not
	 * actually mangled symbols.
	 * 
	 * @param demangleOnlyKnownPatterns True signals to only demangle symbol names that follow 
	 * known mangled patterns.
	 */
	public boolean demangleOnlyKnownPatterns() {
		return demangleOnlyKnownPatterns;
	}

	/**
	 * True signals to only demangle symbol names that follow known mangled patterns.  False triggers
	 * all symbols to be demangled, which results in some symbols getting demangled that were not
	 * actually mangled symbols.
	 * 
	 * @param demangleOnlyKnownPatterns True signals to only demangle symbol names that follow 
	 * known mangled patterns.
	 */
	public void setDemangleOnlyKnownPatterns(boolean demangleOnlyKnownPatterns) {
		this.demangleOnlyKnownPatterns = demangleOnlyKnownPatterns;
	}

}
