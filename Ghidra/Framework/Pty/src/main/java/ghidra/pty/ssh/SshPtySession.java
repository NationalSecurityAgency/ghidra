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
package ghidra.pty.ssh;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.jcraft.jsch.*;

import ghidra.pty.PtySession;

public class SshPtySession implements PtySession {

	private final Channel channel;

	public SshPtySession(Channel channel) {
		this.channel = channel;
	}

	protected int doWaitExited(Long millis) throws InterruptedException, TimeoutException {
		long startMs = System.currentTimeMillis();
		// Doesn't look like there's a clever way to wait. So do the spin sleep :(
		while (!channel.isEOF()) {
			Thread.sleep(100);
			long elapsed = System.currentTimeMillis() - startMs;
			if (millis != null && elapsed > millis) {
				throw new TimeoutException();
			}
		}
		// NB. May not be available
		return channel.getExitStatus();
	}

	@Override
	public int waitExited() throws InterruptedException {
		try {
			return doWaitExited(null);
		}
		catch (TimeoutException e) {
			throw new AssertionError(e);
		}
	}

	@Override
	public int waitExited(long timeout, TimeUnit unit)
			throws InterruptedException, TimeoutException {
		long millis = TimeUnit.MILLISECONDS.convert(timeout, unit);
		return doWaitExited(millis);
	}

	@Override
	public void destroyForcibly() {
		channel.disconnect();
	}

	@Override
	public String description() {
		Session session;
		try {
			session = channel.getSession();
		}
		catch (JSchException e) {
			return "ssh";
		}
		return "ssh " + session.getUserName() + "@" + session.getHost() + ":" + session.getPort();
	}
}
