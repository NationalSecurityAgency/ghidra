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
package ghidra.plugins.fsbrowser.filehandlers;

import java.util.List;

import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import ghidra.formats.gfilesystem.crypto.CachedPasswordProvider;
import ghidra.formats.gfilesystem.crypto.CryptoProviders;
import ghidra.plugins.fsbrowser.*;
import ghidra.util.Msg;

public class ClearCachedPwdFSBFileHandler implements FSBFileHandler {

	private FSBFileHandlerContext context;

	@Override
	public void init(FSBFileHandlerContext context) {
		this.context = context;
	}

	@Override
	public List<DockingAction> createActions() {
		return List.of(new ActionBuilder("FSB Clear Cached Passwords", context.plugin().getName())
				.withContext(FSBActionContext.class)
				.enabledWhen(FSBActionContext::notBusy)
				.popupMenuPath("Clear Cached Passwords")
				.popupMenuGroup("Z", "B")
				.description("Clear cached container file passwords")
				.onAction(ac -> {
					CachedPasswordProvider ccp =
						CryptoProviders.getInstance().getCachedCryptoProvider();
					int preCount = ccp.getCount();
					ccp.clearCache();

					String msg =
						"Cleared %d cached passwords.".formatted(preCount - ccp.getCount());

					Msg.info(this, msg);
					context.fsbComponent().getPlugin().getTool().setStatusInfo(msg);
				})
				.build());
	}
}
