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
package ghidra.pcode.exec;

import java.util.*;

/**
 * The default implemenation of a userop library
 * 
 * <p>
 * Userops are added by calling {@link #putOp(PcodeUseropDefinition)}, usually in the constructor.
 * 
 * @param <T> the type of data processed by the library
 */
public class DefaultPcodeUseropLibrary<T> implements PcodeUseropLibrary<T> {
	protected Map<String, PcodeUseropDefinition<T>> ops = new HashMap<>();
	private Map<String, PcodeUseropDefinition<T>> unmodifiableOps =
		Collections.unmodifiableMap(ops);

	/**
	 * Add the given userop to this library
	 * 
	 * @param userop the userop
	 */
	protected void putOp(PcodeUseropDefinition<T> userop) {
		ops.put(userop.getName(), userop);
	}

	@Override
	public Map<String, PcodeUseropDefinition<T>> getUserops() {
		return unmodifiableOps;
	}
}
