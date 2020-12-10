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

import ghidra.dbg.attributes.TargetObjectRef;
import ghidra.dbg.error.DebuggerIllegalArgumentException;
import ghidra.dbg.gadp.client.annot.GadpAttributeChangeCallback;
import ghidra.dbg.gadp.protocol.Gadp;
import ghidra.dbg.gadp.util.GadpValueUtils;
import ghidra.dbg.target.TargetFocusScope;
import ghidra.dbg.util.PathUtils;
import ghidra.dbg.util.ValueUtils;

public interface GadpClientTargetFocusScope
		extends GadpClientTargetObject, TargetFocusScope<GadpClientTargetFocusScope> {

	@Override
	default CompletableFuture<Void> requestFocus(TargetObjectRef obj) {
		getDelegate().assertValid();
		getModel().assertMine(TargetObjectRef.class, obj);
		// The server should detect this error, but we can detect it here without sending a request
		if (!PathUtils.isAncestor(getPath(), obj.getPath())) {
			throw new DebuggerIllegalArgumentException("Can only focus a successor of the scope");
		}
		return getModel().sendChecked(Gadp.FocusRequest.newBuilder()
				.setPath(GadpValueUtils.makePath(getPath()))
				.setFocus(GadpValueUtils.makePath(obj.getPath())),
			Gadp.FocusReply.getDefaultInstance())
				.thenApply(__ -> null);
	}

	default TargetObjectRef refFromObj(Object obj) {
		return ValueUtils.expectType(obj, TargetObjectRef.class, this, FOCUS_ATTRIBUTE_NAME, this);
	}

	@GadpAttributeChangeCallback(FOCUS_ATTRIBUTE_NAME)
	default void handleFocusChanged(Object focus) {
		getDelegate().listeners.fire(TargetFocusScopeListener.class)
				.focusChanged(this, refFromObj(focus));
	}
}
