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
package agent.gdb.model;

import java.util.List;

import ghidra.dbg.target.TargetAttacher;
import ghidra.dbg.util.PathUtils;

public abstract class AbstractModelForGdbInferiorAttacherTest
		extends AbstractModelForGdbAttacherTest {
	protected static final List<String> INF1_PATH = PathUtils.parse("Inferiors[1]");

	@Override
	public List<String> getExpectedAttacherPath() {
		return INF1_PATH;
	}

	@Override
	public TargetAttacher findAttacher() throws Throwable {
		return m.find(TargetAttacher.class, INF1_PATH);
	}
}
