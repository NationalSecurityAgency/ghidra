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

import agent.lldb.model.AbstractModelForLldbThreadActivationTest;
import ghidra.dbg.util.PathPattern;
import ghidra.dbg.util.PathUtils;

public class InVmModelForLldbThreadActivationTest
		extends AbstractModelForLldbThreadActivationTest {

	@Override
	public List<String> getExpectedSessionPath() {
		return PathUtils.parse("Sessions[]");
	}
	
	protected PathPattern getThreadPattern() {
		return new PathPattern(PathUtils.parse("Sessions[].Processes[].Threads[]"));
	}

	@Override
	protected List<String> getExpectedDefaultActivePath() {
		return PathUtils.parse("Sessions[].Processes[].Threads[]");
	}	

	public String getIdFromCapture(String line) {
		// Syntax "* thread #N:..."
		String[] split = line.split("tid = ");
		split = split[1].split(",");
		Integer decode = Integer.decode(split[0]);
		return Integer.toHexString(decode);
	}
	
	@Override
	public ModelHost modelHost() throws Throwable {
		return new InVmLldbModelHost();
	}


}
