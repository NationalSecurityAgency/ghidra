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
package mdemangler;

/**
 * Options for controlling demangler output.  Quick stub for now.  Full implementation was planned
 * for another ticket
 */
public class MDOutputOptions {

	/**
	 * Default MDMang output option for using the encoded number when outputting an
	 * anonymous namespace node.  This matches the MSFT standard
	 */
	public static final boolean DEFAULT_USE_ANON_NS = false;

	/**
	 * Default MDMang output option for applying user-defined-type (UDT) tags (e.g., "struct")
	 * when the UDT is a template or function argument.  This matches the MSFT standard
	 */
	public static final boolean DEFAULT_APPLY_UDT_TAG = true;

	private boolean useEncodedAnonymousNamespaceNumber = DEFAULT_USE_ANON_NS;
	private boolean applyUdtArgumentTypeTag = DEFAULT_APPLY_UDT_TAG;

	/**
	 * Constructor
	 */
	public MDOutputOptions() {
	}

	/**
	 * Sets the option for whether to use or not use the numerical encoding to craft a
	 * unique anonymous namespace.  The default {@code false} is to produce the normal anonymous
	 * namespace string produced by Microsoft's {@code undname}
	 * @param useEncodedNumber {@code true} to produce a namespace that uses the encoded number
	 */
	public void setUseEncodedAnonymousNamespace(boolean useEncodedNumber) {
		this.useEncodedAnonymousNamespaceNumber = useEncodedNumber;
	}

	/**
	 * Returns {@code true} if the demangler will use the encoded number in creating the
	 * anonymous namespace component
	 * @return {@code true} if the flag is set
	 */
	public boolean useEncodedAnonymousNamespace() {
		return useEncodedAnonymousNamespaceNumber;
	}

	/**
	 * Sets the option for whether to apply user-defined type tags when found as template
	 * or function arguments
	 * @param applyUdtArgumentTypeTag {@code true} to apply the tag on a complex type when
	 * used as a template or function argument
	 */
	public void setApplyUdtArgumentTypeTag(boolean applyUdtArgumentTypeTag) {
		this.applyUdtArgumentTypeTag = applyUdtArgumentTypeTag;
	}

	/**
	 * Returns {@code true} if the demangler will apply user-defined type tags when found as
	 * template or function arguments, such as the "struct" in "templateName<struct A,int>"
	 * @return {@code true} if the flag is set to apply
	 */
	public boolean applyUdtArgumentTypeTag() {
		return applyUdtArgumentTypeTag;
	}

}
