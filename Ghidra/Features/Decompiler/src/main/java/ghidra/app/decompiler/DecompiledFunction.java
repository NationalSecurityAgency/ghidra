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
package ghidra.app.decompiler;

/**
 * A class to hold pieces of a decompiled function.
 */
public class DecompiledFunction {
	private String signature;
	private String c;

	/**
	 * Constructs a new decompiled function.
	 * @param signature the function signature or prototype (eg, "int foo(double d)")
	 * @param c the complete C code of the function.
	 */
	public DecompiledFunction(String signature, String c) {
		this.signature = signature;
		this.c = c;
	}

	/**
	 * Returns the function signature or prototype (eg, "int foo(double d)").
	 * @return the function signature or prototype (eg, "int foo(double d)")
	 */
	public String getSignature() {
		return signature;
	}

	/**
	 * Returns the complete C code of the function.
	 * @return the complete C code of the function
	 */
	public String getC() {
		return c;
	}
}
