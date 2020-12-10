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
package ghidra.trace.util;

public class MethodProtector {
	private boolean inUse;

	public interface TemperamentalCallable<E extends Throwable> {
		void run() throws E;
	}

	public <E extends Throwable> void take(TemperamentalCallable<E> callable) throws E {
		if (inUse) {
			return;
		}
		try {
			inUse = true;
			callable.run();
		}
		finally {
			inUse = false;
		}
	}

	public <E extends Throwable> void avoid(TemperamentalCallable<E> callable) throws E {
		if (inUse) {
			return;
		}
		callable.run();
	}
}
