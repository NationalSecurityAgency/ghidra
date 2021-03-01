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

import ghidra.dbg.gadp.client.annot.GadpAttributeChangeCallback;
import ghidra.dbg.gadp.protocol.Gadp;
import ghidra.dbg.target.TargetInterpreter;
import ghidra.dbg.util.ValueUtils;

public interface GadpClientTargetInterpreter extends GadpClientTargetObject, TargetInterpreter {

	@Override
	default CompletableFuture<Void> execute(String cmd) {
		getDelegate().assertValid();
		return getModel().sendChecked(Gadp.ExecuteRequest.newBuilder()
				.setPath(GadpValueUtils.makePath(getPath()))
				.setCommand(cmd),
			Gadp.ExecuteReply.getDefaultInstance())
				.thenApply(rep -> null);
	}

	@Override
	default CompletableFuture<String> executeCapture(String cmd) {
		getDelegate().assertValid();
		return getModel().sendChecked(Gadp.ExecuteRequest.newBuilder()
				.setPath(GadpValueUtils.makePath(getPath()))
				.setCommand(cmd)
				.setCapture(true),
			Gadp.ExecuteReply.getDefaultInstance())
				.thenApply(rep -> rep.getCaptured());
	}

	default String promptFromObj(Object obj) {
		return ValueUtils.expectType(obj, String.class, this, PROMPT_ATTRIBUTE_NAME, ">", true);
	}

	@GadpAttributeChangeCallback(PROMPT_ATTRIBUTE_NAME)
	default void handlePromptChanged(Object prompt) {
		getDelegate().getListeners()
				.fire(TargetInterpreterListener.class)
				.promptChanged(this, promptFromObj(prompt));
	}
}
