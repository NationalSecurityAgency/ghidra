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
package ghidra.framework.plugintool;

import java.util.*;

import ghidra.framework.plugintool.util.ServiceListener;

public class ServiceProviderDecorator implements ServiceProvider {

	private ServiceProvider delegate;

	private Map<Class<?>, Object> overriddenServices = new HashMap<>();

	public static ServiceProviderDecorator decorate(ServiceProvider delegate) {
		return new ServiceProviderDecorator(delegate);
	}

	public static ServiceProviderDecorator createEmptyDecorator() {
		return new ServiceProviderDecorator(new ServiceProviderStub());
	}

	private ServiceProviderDecorator(ServiceProvider delegate) {
		this.delegate = Objects.requireNonNull(delegate);
	}

	/**
	 * Adds a service that will override any service contained in the delegate 
	 * {@link ServiceProvider}. 
	 * 
	 * <P>Note: this will not notify any clients that services have been changed.  This means 
	 * that you should call this method before passing this service provider on to your clients.
	 * 
	 * @param serviceClass the service class
	 * @param service the service implementation
	 */
	public <T> void overrideService(Class<T> serviceClass, Object service) {
		overriddenServices.put(serviceClass, service);
	}

	@Override
	public <T> T getService(Class<T> serviceClass) {
		Object service = overriddenServices.get(serviceClass);
		if (service != null) {
			return serviceClass.cast(service);
		}
		return delegate.getService(serviceClass);
	}

	@Override
	public void addServiceListener(ServiceListener listener) {
		delegate.addServiceListener(listener);
	}

	@Override
	public void removeServiceListener(ServiceListener listener) {
		delegate.removeServiceListener(listener);
	}

}
