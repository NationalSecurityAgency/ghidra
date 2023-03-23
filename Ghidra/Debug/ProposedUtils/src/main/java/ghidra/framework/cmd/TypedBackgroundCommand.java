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
package ghidra.framework.cmd;

import ghidra.framework.model.DomainObject;
import ghidra.framework.model.UndoableDomainObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.task.TaskMonitor;

public abstract class TypedBackgroundCommand<T extends UndoableDomainObject>
		extends BackgroundCommand {

	public TypedBackgroundCommand(String name, boolean hasProgress, boolean canCancel,
			boolean isModal) {
		super(name, hasProgress, canCancel, isModal);
	}

	@Override
	@SuppressWarnings("unchecked")
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		return applyToTyped((T) obj, monitor);
	}

	public abstract boolean applyToTyped(T obj, TaskMonitor monitor);

	public void run(PluginTool tool, T obj) {
		tool.executeBackgroundCommand(this, obj);
	}
}
