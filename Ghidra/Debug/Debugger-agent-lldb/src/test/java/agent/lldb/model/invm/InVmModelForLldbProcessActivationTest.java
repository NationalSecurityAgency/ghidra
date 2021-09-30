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
package agent.lldb.model.invm;

import java.util.List;

import agent.lldb.model.AbstractModelForLldbProcessActivationTest;
import ghidra.dbg.util.PathPattern;
import ghidra.dbg.util.PathUtils;

public class InVmModelForLldbProcessActivationTest
		extends AbstractModelForLldbProcessActivationTest {

	@Override
	public List<String> getExpectedSessionPath() {
		return PathUtils.parse("Sessions[]");
	}

	protected PathPattern getProcessPattern() {
		return new PathPattern(PathUtils.parse("Sessions[].Processes[]"));
	}

	@Override
	protected List<String> getExpectedDefaultActivePath() {
		return PathUtils.parse("Sessions[3].Processes[]");
	}	
	
	public String getIdFromCapture(String line) {
		// Syntax "* process #N:..."
		String[] split = line.split("pid=");
		split = split[1].split(",");
		return split[0];
	}
	
	public String getIndexFromCapture(String line) {
		// Syntax "* target #N:..."
		String[] split = line.split("#");
		split = split[1].split(":");
		return split[0];
	}	
	
	@Override
	public ModelHost modelHost() throws Throwable {
		return new InVmLldbModelHost();
	}

}
