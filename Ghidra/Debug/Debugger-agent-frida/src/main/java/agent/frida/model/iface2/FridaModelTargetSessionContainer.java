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
package agent.frida.model.iface2;

import agent.frida.manager.FridaCause;
import agent.frida.manager.FridaEventsListenerAdapter;
import agent.frida.manager.FridaSession;

public interface FridaModelTargetSessionContainer
		extends FridaModelTargetObject, FridaEventsListenerAdapter {

	@Override
	public void sessionAdded(FridaSession session, FridaCause cause);
	
	@Override
	public void sessionReplaced(FridaSession session, FridaCause cause);

	@Override
	public void sessionRemoved(String sessionId, FridaCause cause);

	public FridaModelTargetSession getTargetSession(FridaSession session);

}
