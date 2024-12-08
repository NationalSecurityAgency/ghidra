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
package ghidra.app.util.viewer.proxy;

import ghidra.program.model.address.Address;

/**
 * Used as proxy for a null value.
 */
public class EmptyProxy extends ProxyObj<Object> {
	public static final EmptyProxy EMPTY_PROXY = new EmptyProxy();

	/**
	 * Construct an empty proxy
	 */
	private EmptyProxy() {
		super(null);
	}

	@Override
	public Object getObject() {
		return null;
	}

	@Override
	public boolean contains(Address a) {
		return false;
	}
}
