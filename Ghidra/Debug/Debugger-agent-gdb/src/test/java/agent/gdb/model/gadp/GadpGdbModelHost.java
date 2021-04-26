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
package agent.gdb.model.gadp;

import static org.junit.Assume.assumeFalse;
import static org.junit.Assume.assumeTrue;

import java.io.File;

import agent.gdb.gadp.GdbLocalDebuggerModelFactory;
import agent.gdb.model.AbstractGdbModelHost;
import ghidra.dbg.DebuggerModelFactory;
import ghidra.util.SystemUtilities;

class GadpGdbModelHost extends AbstractGdbModelHost {
	@Override
	public DebuggerModelFactory getModelFactory() {
		assumeFalse("Not ready for CI", SystemUtilities.isInTestingBatchMode());
		assumeTrue("GDB cannot be found", new File("/usr/bin/gdb").canExecute());
		return new GdbLocalDebuggerModelFactory();
	}
}
