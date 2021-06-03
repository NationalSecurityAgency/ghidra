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
package agent.gdb.pty.ssh;

import java.io.IOException;
import java.io.InterruptedIOException;

import agent.gdb.pty.PtySession;
import ch.ethz.ssh2.ChannelCondition;
import ch.ethz.ssh2.Session;

public class SshPtySession implements PtySession {

	private final Session session;

	public SshPtySession(Session session) {
		this.session = session;
	}

	@Override
	public Integer waitExited() throws InterruptedException {
		try {
			session.waitForCondition(ChannelCondition.EOF, 0);
			// NB. May not be available
			return session.getExitStatus();
		}
		catch (InterruptedIOException e) {
			throw new InterruptedException();
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public void destroyForcibly() {
		/**
		 * TODO: This is imperfect, since it terminates the whole SSH session, not just the pty
		 * session. I don't think that's terribly critical for our use case, but we should adjust
		 * the spec to account for this, or devise a better implementation.
		 */
		session.close();
	}
}
