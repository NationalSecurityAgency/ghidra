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
package ghidra.dbg.gadp.client;

import java.util.concurrent.CompletableFuture;

import ghidra.dbg.error.DebuggerIllegalArgumentException;
import ghidra.dbg.gadp.protocol.Gadp;
import ghidra.dbg.target.TargetActiveScope;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.PathUtils;

public interface GadpClientTargetActiveScope extends GadpClientTargetObject, TargetActiveScope {

	@Override
	default CompletableFuture<Void> requestActivation(TargetObject obj) {
		getDelegate().assertValid();
		getModel().assertMine(TargetObject.class, obj);
		// The server should detect this error, but we can detect it here without sending a request
		if (!PathUtils.isAncestor(getPath(), obj.getPath())) {
			throw new DebuggerIllegalArgumentException(
				"Can only activate a successor of the scope");
		}
		return getModel()
				.sendChecked(
					Gadp.ActivationRequest.newBuilder()
							.setPath(GadpValueUtils.makePath(getPath()))
							.setActive(GadpValueUtils.makePath(obj.getPath())),
					Gadp.ActivationReply.getDefaultInstance())
				.thenApply(__ -> null);
	}
}
