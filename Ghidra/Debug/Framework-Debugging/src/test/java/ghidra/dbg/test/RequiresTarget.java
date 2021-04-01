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
package ghidra.dbg.test;

import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetProcess;
import ghidra.dbg.testutil.DebuggerModelTestUtils;

public interface RequiresTarget extends DebuggerModelTestUtils {

	/**
	 * Perform whatever minimal setup is necessary to obtain a target suitable for testing
	 * 
	 * <p>
	 * For user-mode debugging this is almost certainly a {@link TargetProcess}.
	 * 
	 * @return the target
	 * @throws Throwable if anything goes wrong
	 */
	TargetObject obtainTarget() throws Throwable;
}
