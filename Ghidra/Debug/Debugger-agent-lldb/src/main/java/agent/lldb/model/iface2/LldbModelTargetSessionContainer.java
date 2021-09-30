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

import SWIG.SBTarget;
import agent.lldb.manager.LldbCause;
import agent.lldb.manager.LldbEventsListenerAdapter;

public interface LldbModelTargetSessionContainer
		extends LldbModelTargetObject, LldbEventsListenerAdapter {

	@Override
	public void sessionAdded(SBTarget session, LldbCause cause);
	
	@Override
	public void sessionReplaced(SBTarget session, LldbCause cause);

	@Override
	public void sessionRemoved(String sessionId, LldbCause cause);

	public LldbModelTargetSession getTargetSession(SBTarget session);

}
