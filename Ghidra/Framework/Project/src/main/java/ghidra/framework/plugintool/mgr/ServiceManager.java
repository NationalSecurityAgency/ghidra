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
package ghidra.framework.plugintool.mgr;

import java.util.*;

import ghidra.framework.plugintool.ServiceInterfaceImplementationPair;
import ghidra.framework.plugintool.util.ServiceListener;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.AssertException;

/**
 * Class for managing plugin services. A plugin may provide a service, or
 * it may depend on a service. The ServiceManager maintains a list of
 * service names and plugins that provide those services. A plugin may
 * dynamically add and remove services from the service registry. As services
 * are added and removed, all the plugins (ServiceListener) 
 * in the tool are notified.
 */

public class ServiceManager {
	private Map<Class<?>, List<Object>> servicesByInterface;
	private WeakSet<ServiceListener> serviceListeners;
	private boolean notifyAdd = true;
	private List<Object[]> notifications = new ArrayList<>();

	/**
	 * Construct a new Service Registry.
	 */
	public ServiceManager() {
		servicesByInterface = new HashMap<>();
		serviceListeners = WeakDataStructureFactory.createSingleThreadAccessWeakSet();
	}

	/**
	 * Add listener that is notified when services are added or removed.
	 * @param listener listener to notify
	 */
	public void addServiceListener(ServiceListener listener) {
		serviceListeners.add(listener);
	}

	/**
	 * Remove the given listener from list of listeners notified when
	 * services are added or removed.
	 * @param listener listener to remove
	 */
	public void removeServiceListener(ServiceListener listener) {
		serviceListeners.remove(listener);
	}

	/**
	 * Set the indicator for whether service listeners should be notified.
	 * While plugins are being restored from a tool state, this indicator
	 * is false, as a plugin may not be in the proper state to handle the
	 * notification.
	 * @param b true means to notify listeners of the services added to
	 * the tool
	 */
	public synchronized void setServiceAddedNotificationsOn(boolean b) {
		notifyAdd = b;
		if (notifyAdd) {
			Iterator<Object[]> it = notifications.iterator();
			while (it.hasNext()) {
				Object[] arr = it.next();
				notifyServiceAdded((Class<?>) arr[0], arr[1]);
				it.remove();
			}
		}
	}

	private void notifyServiceAdded(Class<?> interfaceClass, Object service) {
		Iterator<?> it = serviceListeners.iterator();
		while (it.hasNext()) {
			((ServiceListener) it.next()).serviceAdded(interfaceClass, service);
		}
	}

	/**
	 * Add the service to the tool. Notify the service listeners if the
	 * notification indicator is true; otherwise, add the service to a list
	 * that will be used to notify listeners when notifications are 
	 * turned on again.
	 * @param interfaceClass class of the service interface being added
	 * @param service implementation of the service; it may be a plugin or
	 * may be some object created by the plugin
	 * 
	 * @see #setServiceAddedNotificationsOn(boolean) 
	 */
	public synchronized <T> void addService(Class<? extends T> interfaceClass, T service) {
		List<Object> list =
			servicesByInterface.computeIfAbsent(interfaceClass, (k) -> new ArrayList<>());
		if (list.contains(service)) {
			throw new AssertException(
				"Same Service implementation cannot be " + "added more than once");
		}

		list.add(service);
		if (notifyAdd) {
			notifyServiceAdded(interfaceClass, service);
		}
		else {
			notifications.add(new Object[] { interfaceClass, service });
		}
	}

	/**
	 * Remove the service from the tool.
	 */
	public void removeService(Class<?> interfaceClass, Object service) {
		List<Object> list = servicesByInterface.get(interfaceClass);
		if (list != null) {
			list.remove(service);
			if (list.size() == 0) {
				servicesByInterface.remove(interfaceClass);
			}
		}
		for (ServiceListener serviceListener : serviceListeners) {
			serviceListener.serviceRemoved(interfaceClass, service);
		}
	}

	/**
	 * Return the first implementation found for the given service class.
	 * @param interfaceClass interface class for the service
	 * @return null if the interfaceClass was not registered
	 */
	public <T> T getService(Class<T> interfaceClass) {
		List<Object> list = servicesByInterface.get(interfaceClass);
		if (list == null) {
			return null;
		}
		Object object = list.get(0);
		return interfaceClass.cast(object);
	}

	/**
	 * Get an array of objects that implement the given interfaceClass.
	 * @param interfaceClass interface class for the service
	 * @return zero length array if the interfaceClass was not registered
	 */
	@SuppressWarnings("unchecked")
	// new array instance is OK
	public <T> T[] getServices(Class<T> interfaceClass) {
		List<Object> list = servicesByInterface.get(interfaceClass);
		if (list == null) {
			return (T[]) java.lang.reflect.Array.newInstance(interfaceClass, 0);
		}
		T[] objs = (T[]) java.lang.reflect.Array.newInstance(interfaceClass, list.size());
		return list.toArray(objs);
	}

	/**
	 * Returns true if the specified <code>serviceInterface</code>
	 * is a valid service that exists in this service manager.
	 * @param serviceInterface the service interface
	 * @return true if the specified <code>serviceInterface</code>
	 */
	public boolean isService(Class<?> serviceInterface) {
		for (Class<?> serviceClass : servicesByInterface.keySet()) {
			if (serviceClass.equals(serviceInterface)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Returns a array of all service implementors.
	 * @return a array of all service implementors
	 */
	public List<ServiceInterfaceImplementationPair> getAllServices() {
		List<ServiceInterfaceImplementationPair> list = new ArrayList<>();
		for (Class<?> serviceClass : servicesByInterface.keySet()) {
			for (Object serviceImpl : servicesByInterface.get(serviceClass)) {
				list.add(new ServiceInterfaceImplementationPair(serviceClass, serviceImpl));
			}
		}
		return list;
	}
}
