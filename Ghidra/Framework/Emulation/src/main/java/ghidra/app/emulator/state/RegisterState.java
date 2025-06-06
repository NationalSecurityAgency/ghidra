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
package ghidra.app.emulator.state;

import java.util.List;
import java.util.Set;

public interface RegisterState {

	public Set<String> getKeys();

	/**
	 * Get the byte array value for a register name
	 * 
	 * @param key the register name
	 * @return a list (used as an optional) containing at most the one byte array giving the
	 *         register's value. If empty, the value if unspecified.
	 */
	public List<byte[]> getVals(String key);

	/**
	 * Check if the register is initialized
	 * 
	 * @param key the register name
	 * @return a list (used as an optional) containing at most the one initialization state. True if
	 *         initialized, false if not. Empty if unspecified.
	 */
	public List<Boolean> isInitialized(String key);

	public void setVals(String key, byte[] vals, boolean setInitiailized);

	public void setVals(String key, long val, int size, boolean setInitiailized);

	public void dispose();

}
