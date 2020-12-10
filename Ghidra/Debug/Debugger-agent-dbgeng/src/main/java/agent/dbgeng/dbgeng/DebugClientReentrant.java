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
package agent.dbgeng.dbgeng;

/**
 * An interface containing the subset of {@link DebugClient} methods which are reentrant.
 * 
 * All other methods should be called only by the thread which created the client.
 */
public interface DebugClientReentrant {
	/**
	 * Create a new client for the calling thread, connected to the same session as this client.
	 * 
	 * @return the new client
	 */
	DebugClient createClient();

	/**
	 * Get the reentrant control interface to the client
	 * 
	 * @return the control interface
	 */
	DebugControlReentrant getControl();

	/**
	 * End a session without acquiring locks
	 * 
	 * Note. This method calls {@code IDebugClient::EndSession(DEBUG_END_REENTRANT)}. Per the MSDN,
	 * this may leave the engine in an indeterminate state. The engine should no longer be used by
	 * this process. It's really only appropriate to use this method when terminating the debugger.
	 */
	void endSessionReentrant();
}
