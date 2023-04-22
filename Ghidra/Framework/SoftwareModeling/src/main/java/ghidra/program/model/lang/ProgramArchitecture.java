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
package ghidra.program.model.lang;

import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.OverlayAddressSpace;
import ghidra.program.model.listing.Program;

/**
 * <code>ProgramArchitecture</code> which identifies program architecture details required to 
 * utilize language/compiler-specific memory and variable storage specifications.
 */
public interface ProgramArchitecture {

	/**
	 * Get the processor language
	 * @return processor language
	 */
	Language getLanguage();

	/**
	 * Get the address factory for this architecture.  In the case of a {@link Program} this should 
	 * be the extended address factory that includes the stack space and any defined overlay
	 * spaces (i.e., {@link OverlayAddressSpace}).
	 * @return address factory
	 */
	AddressFactory getAddressFactory();

	/**
	 * Get the compiler specification
	 * @return compiler specification
	 */
	CompilerSpec getCompilerSpec();

	/**
	 * Get the language/compiler spec ID pair associated with this program architecture.
	 * @return language/compiler spec ID pair
	 */
	public default LanguageCompilerSpecPair getLanguageCompilerSpecPair() {
		return new LanguageCompilerSpecPair(getLanguage().getLanguageID(),
			getCompilerSpec().getCompilerSpecID());
	}

}
