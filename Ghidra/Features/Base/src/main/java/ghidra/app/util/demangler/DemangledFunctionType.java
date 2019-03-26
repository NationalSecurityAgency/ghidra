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
 * An extension of {@link DemangledType} that signals that the type is function and can provide
 * more info, like the function signature.
 */
public class DemangledFunctionType extends DemangledType {

	private String signature;

	public DemangledFunctionType(String name, String signature) {
		super(name);
		this.signature = signature;
	}

	@Override
	public boolean isFunction() {
		return true;
	}

	public String getSignature() {
		return signature;
	}
}
