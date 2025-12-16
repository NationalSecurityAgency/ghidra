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
package ghidra.app.plugin.core.navigation.locationreferences;

import java.util.ArrayList;
import java.util.List;

import docking.ActionContext;
import docking.DefaultActionContext;

/**
 * An {@link ActionContext} for the {@link LocationReferencesProvider}.
 */
public class LocationReferencesProviderContext extends DefaultActionContext {

	private LocationReferencesProvider locationProvider;
	private List<LocationReference> selectedReferences;

	public LocationReferencesProviderContext(LocationReferencesProvider provider) {
		super(provider, provider.getTable());
		this.locationProvider = provider;
	}

	public List<LocationReference> getSelectedReferences() {
		if (selectedReferences == null) {
			LocationReferencesPanel panel = locationProvider.getPanel();
			selectedReferences = panel.getSelectedReferences();
		}

		return selectedReferences;
	}

	public List<LocationReference> getDeletableReferences() {
		List<LocationReference> results = new ArrayList<>();
		List<LocationReference> refs = getSelectedReferences();
		for (LocationReference lr : refs) {
			if (lr.isDeletable()) {
				results.add(lr);
			}
		}
		return results;
	}
}
