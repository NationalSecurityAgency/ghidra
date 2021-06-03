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

import ch.ethz.ssh2.KnownHosts;
import ch.ethz.ssh2.ServerHostKeyVerifier;
import docking.widgets.OptionDialog;
import ghidra.util.Msg;

public class GhidraSshHostKeyVerifier implements ServerHostKeyVerifier {

	private final KnownHosts database;

	public GhidraSshHostKeyVerifier(KnownHosts database) {
		this.database = database;
	}

	@Override
	public boolean verifyServerHostKey(String hostname, int port, String serverHostKeyAlgorithm,
			byte[] serverHostKey) throws Exception {
		switch (database.verifyHostkey(hostname, serverHostKeyAlgorithm, serverHostKey)) {
			case KnownHosts.HOSTKEY_IS_OK:
				return true;
			case KnownHosts.HOSTKEY_IS_NEW:
				int response = OptionDialog.showYesNoDialogWithNoAsDefaultButton(null,
					"Unknown SSH Server Host Key",
					"<html><b>The server " + hostname + " is not known.</b> " +
						"It is highly recommended you log in to the server using a standard " +
						"SSH client to confirm the host key first.<br><br>" +
						"Do you want to continue?</html>");
				return response == OptionDialog.YES_OPTION;
			case KnownHosts.HOSTKEY_HAS_CHANGED:
				Msg.showError(this, null, "SSH Server Host Key Changed",
					"<html><b>The server " + hostname + " has a different key than before!</b>" +
						"Use a standard SSH client to resolve the issue.</html>");
				return false;
			default:
				throw new IllegalStateException();
		}
	}
}
