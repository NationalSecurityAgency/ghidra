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
package docking;

import java.awt.Component;

import ghidra.util.Msg;

/**
 * Action context for {@link DialogComponentProvider}s.
 */
public class DialogActionContext extends DefaultActionContext {

	public DialogActionContext(DialogComponentProvider dialogProvider, Component sourceComponent) {
		super(null, dialogProvider, sourceComponent);
	}

	public DialogComponentProvider getDialogComponentProvider() {
		Object contextObject = getContextObject();
		if (contextObject instanceof DialogComponentProvider dcp) {
			return dcp;
		}

		Msg.warn(this, "Found dialog context without a DialogComponentProvider context object");
		return null;
	}
}
