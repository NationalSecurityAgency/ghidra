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

public abstract class MergeableBackgroundCommand<T extends DomainObject>
		extends BackgroundCommand<T> {

	public MergeableBackgroundCommand(String name, boolean hasProgress, boolean canCancel,
			boolean isModal) {
		super(name, hasProgress, canCancel, isModal);
	}

	/**
	 * Merges the properties of the two commands
	 * @param command command to be merged with this one
	 * @return resulting merged command
	 */
	public abstract MergeableBackgroundCommand<T> mergeCommands(
			MergeableBackgroundCommand<T> command);
}
