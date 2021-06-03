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
package agent.dbgmodel.model.invm;

import java.util.List;

import agent.dbgeng.model.AbstractModelForDbgengThreadActivationTest;
import ghidra.dbg.target.TargetInterpreter;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.PathPattern;
import ghidra.dbg.util.PathUtils;

public class InVmModelForDbgmodelThreadActivationTest
		extends AbstractModelForDbgengThreadActivationTest {

	protected PathPattern getThreadPattern() {
		return new PathPattern(PathUtils.parse("Sessions[0x0].Processes[].Threads[]"));
	}

	@Override
	public ModelHost modelHost() throws Throwable {
		return new InVmDbgmodelModelHost();
	}

	@Override
	public List<String> getExpectedSessionPath() {
		return PathUtils.parse("Sessions[0x0]");
	}

	public String getIdFromCapture(String line) {
		return "0x" + line.split("\\s+")[3].split("\\.")[1];
	}

	@Override
	protected void activateViaInterpreter(TargetObject obj, TargetInterpreter interpreter)
			throws Throwable {
		String threadId = obj.getName();
		threadId = threadId.substring(3, threadId.length() - 1);
		String output = waitOn(interpreter.executeCapture("~"));
		String[] lines = output.split("\n");
		for (String l : lines) {
			if (l.contains(threadId)) {
				threadId = l.split("\\s+")[1];
				break;
			}
		}
		waitOn(interpreter.execute("~" + threadId + " s"));
	}

}
