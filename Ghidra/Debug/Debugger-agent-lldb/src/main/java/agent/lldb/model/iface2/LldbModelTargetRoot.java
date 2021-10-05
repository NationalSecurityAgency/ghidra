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
package agent.lldb.model.iface2;

import agent.lldb.manager.LldbEventsListenerAdapter;
import agent.lldb.model.iface1.LldbModelTargetAccessConditioned;
import agent.lldb.model.iface1.LldbModelTargetActiveScope;
import agent.lldb.model.iface1.LldbModelTargetAttacher;
import agent.lldb.model.iface1.LldbModelTargetEventScope;
import agent.lldb.model.iface1.LldbModelTargetFocusScope;
import agent.lldb.model.iface1.LldbModelTargetLauncher;

public interface LldbModelTargetRoot extends //
		///LldbModelTargetObject,
		LldbModelTargetAccessConditioned, //
		LldbModelTargetAttacher, //
		LldbModelTargetActiveScope, //
		LldbModelTargetEventScope, //
		LldbModelTargetLauncher, //
		LldbModelTargetFocusScope, //
		LldbEventsListenerAdapter {

	void setDefaultConnector(LldbModelTargetConnector defaultConnector);

	// getActive & requestActivation implemented by LldbModelTargetObject & LldbModelTargetActiveScope 
	// getFocus & requestFocus implemented by LldbModelTargetObject & LldbModelTargetFocusScope 
}
