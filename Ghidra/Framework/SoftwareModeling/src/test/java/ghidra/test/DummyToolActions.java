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
package ghidra.test;

import java.util.Set;

import docking.ComponentProvider;
import docking.action.DockingActionIf;
import docking.actions.DockingToolActions;
import docking.actions.SharedDockingActionPlaceholder;

public class DummyToolActions implements DockingToolActions {

	@Override
	public void addLocalAction(ComponentProvider provider, DockingActionIf action) {
		// stub
	}

	@Override
	public void addGlobalAction(DockingActionIf action) {
		// stub
	}

	@Override
	public void removeGlobalAction(DockingActionIf action) {
		// stub
	}

	@Override
	public void removeActions(String owner) {
		// stub
	}

	@Override
	public DockingActionIf getLocalAction(ComponentProvider provider, String actionName) {
		return null;
	}

	@Override
	public Set<DockingActionIf> getActions(String owner) {
		return null;
	}

	@Override
	public Set<DockingActionIf> getAllActions() {
		return null;
	}

	@Override
	public void removeLocalAction(ComponentProvider provider, DockingActionIf action) {
		// stub
	}

	@Override
	public void removeActions(ComponentProvider provider) {
		// stub
	}

	@Override
	public void registerSharedActionPlaceholder(SharedDockingActionPlaceholder placeholder) {
		// stub
	}
}
