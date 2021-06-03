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
package agent.dbgmodel.gadp;

import agent.dbgeng.gadp.DbgEngLocalDebuggerModelFactory;
import ghidra.dbg.util.ConfigurableFactory.FactoryDescription;
import ghidra.util.classfinder.ExtensionPointProperties;

@FactoryDescription( //
		brief = "MS dbgmodel.dll (WinDbg 2) local agent via GADP/TCP", //
		htmlDetails = "Launch a new agent using the Microsoft Debug Model (best for WinDbg 2)." //
)
@ExtensionPointProperties(priority = 90)
public class DbgModelLocalDebuggerModelFactory extends DbgEngLocalDebuggerModelFactory {

	@Override
	protected String getThreadName() {
		return "Local dbgmodel.dll Agent stdout";
	}

	@Override
	protected Class<?> getServerClass() {
		return DbgModelGadpServer.class;
	}
}
