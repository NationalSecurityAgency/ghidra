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
package ghidra.dbg.testutil;

import ghidra.util.Msg;

public class CatchOffThread implements AutoCloseable {
	protected Throwable caught;

	public void catching(Runnable runnable) {
		try {
			runnable.run();
		}
		catch (Throwable e) {
			if (caught == null) {
				caught = e;
			}
			Msg.error(this, "Off-thread exception: " + e);
		}
	}

	@Override
	public void close() throws Exception {
		if (caught != null) {
			if (caught instanceof Exception) {
				throw (Exception) caught;
			}
			else {
				throw new AssertionError("Off-thread exception", caught);
			}
		}
	}
}
