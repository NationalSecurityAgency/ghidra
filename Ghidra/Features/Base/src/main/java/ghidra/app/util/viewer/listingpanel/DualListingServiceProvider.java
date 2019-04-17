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
package ghidra.app.util.viewer.listingpanel;

import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.util.ServiceListener;

/**
 * This provides services, but overrides and implements its own goTo for one of the listing 
 * panels in a dual listing code comparison panel.
 * If a goTo service is requested, this provides a goTo service that limits where you can go.
 * It constrains the goTo to addresses that are currently in the indicated listing panel of 
 * the dual listing code comparison panel.
 */
class DualListingServiceProvider implements ServiceProvider {
	
	private ServiceProvider serviceProvider;
	private DualListingGoToService dualListingGoToService;
	
	/**
	 * Constructor for a DualListingServiceProvider.
	 * @param serviceProvider the service provider to use for acquiring services other than goTo.
	 * @param panel the dual listing code comparison panel.
	 * @param isLeftPanel true indicates this is the left listing panel of the dual panel. 
	 * false indicates the right panel.
	 */
	DualListingServiceProvider(ServiceProvider serviceProvider, ListingCodeComparisonPanel panel,
			boolean isLeftPanel) {
		this.serviceProvider = serviceProvider;
		GoToService goToService = serviceProvider.getService(GoToService.class);
		this.dualListingGoToService = new DualListingGoToService(goToService, panel, isLeftPanel);
	}

	@Override
	public void addServiceListener(ServiceListener listener) {
		serviceProvider.addServiceListener(listener);
	}

	@Override
	public <T> T getService(Class<T> serviceClass) {
		if (serviceClass == GoToService.class) {
			return serviceClass.cast(dualListingGoToService);
		}
		return serviceProvider.getService(serviceClass);
	}

	@Override
	public void removeServiceListener(ServiceListener listener) {
		serviceProvider.removeServiceListener(listener);
	}

}
