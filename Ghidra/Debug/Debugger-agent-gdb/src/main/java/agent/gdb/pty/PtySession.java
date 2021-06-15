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
package agent.gdb.pty;

/**
 * A session led by the child pty
 * 
 * <p>
 * This is typically a handle to the (local or remote) process designated as the "session leader"
 */
public interface PtySession {

	/**
	 * Wait for the session leader to exit, returning its optional exit status code
	 * 
	 * @return the status code, if applicable and implemented
	 * @throws InterruptedException if the wait is interrupted
	 */
	Integer waitExited() throws InterruptedException;

	/**
	 * Take the greatest efforts to terminate the session (leader and descendants)
	 * 
	 * <p>
	 * If this represents a remote session, this should strive to release the remote resources
	 * consumed by this session. If that is not possible, this should at the very least release
	 * whatever local resources are used in maintaining and controlling the remote session.
	 */
	void destroyForcibly();
}
