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
package ghidra.app.plugin.core.debug.client.tracermi;

import java.util.HashSet;
import java.util.Set;

public class RmiBatch  {


	private int refCount = 0;
	private Set<Object> futures = new HashSet<>();

	public void inc() {
		refCount++;
	}

	public int dec() {
		return --refCount;
	}
	
	public void append(Object f) {
		futures.add(f);
	}

	public Object results() {
		return null;
	}


}
