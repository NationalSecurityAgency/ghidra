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

import docking.ComponentProvider;
import docking.action.DockingAction;
import ghidra.framework.main.*;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.util.*;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.classfinder.ExtensionPoint;

/**
 * Plugins are a basic building block in Ghidra, used to bundle features or capabilities
 * into a unit that can be enabled or disabled by the user in their Tool.
 * <p>
 * Plugins expose their features or capabilities to users via menu items and buttons that
 * the user can click on, and via "service" APIs that other Plugins can programmatically subscribe
 * to, and via {@link PluginEvent}s that are broadcast.
 * <p>
 * <h2>Well formed Plugins:</h2>
 * <UL>
 * 	<LI>Derive from <code>Plugin</code> (directly or indirectly).
 * 	<LI>Class name ends with "Plugin" and does not match any other Plugin, regardless of
 * 	its location in the package tree.
 * 	<LI>Have a {@link PluginInfo @PluginInfo()} annotation.
 * 	<LI>Have a constructor with exactly 1 parameter: PluginTool.
 * 		<UL>
 *  			<LI><code>public MyPlugin(PluginTool tool) { ... }</code>
 *  		</UL>
 *  	<LI>Usually overrides <code>protected void init()</code>.
 * </UL>
 * <h2>Class naming</h2>
 * All Plugin Classes <b>MUST END IN</b> "Plugin".  If not, the ClassSearcher will not find them.
 * <p>
 * Some special Plugins marked with the {@link ProgramaticUseOnly} interface are manually
 * created and do not follow this naming requirement.
 *
 * <h2>Plugin Life cycle</h2>
 * <OL>
 * 	<LI>Your Plugin's constructor is called
 * 		<OL>
 * 			<LI>Plugin base class constructor is called.
 * 				<OL>
 * 					<LI>Services listed in the @PluginInfo annotation are automatically added
 * 					to dependency list
 * 				</OL>
 * 			<LI>Your Plugin publishes any services listed in PluginInfo using
 * 			{@link Plugin#registerServiceProvided(Class, Object) registerServiceProvided()}.
 * 			(required)
 *  			<LI>Create Actions (optional)
 *  			<LI>Register {@link ghidra.framework.options.Options Options} with the
 * {@link PluginTool#getOptions(String)}. (optional)<br>
 * 		</OL>
 * 	<LI>Other Plugins are constructed, dependencies evaluated, etc.<br>
 * 	If your dependencies are not available (ie. not installed, threw an exception during their
 *	initialization, etc), your Plugin's {@link #dispose()} will be called and then your Plugin
 *	instance will be discarded.<br>
 *	<LI>Your Plugin's {@link #init()} method is called (when its dependencies are met).
 * 		<OL>
 * 			<LI>Call {@link PluginTool#getService(Class)} to get service
 * 			implementations. (the service class being requested should already be
 * 			listed in the @PluginInfo)
 * 			<LI>Create Actions (optional)
 * 			<LI>Other initialization stuff.
 * 		</OL>
 *	<LI>Your Plugin's {@link #readConfigState(SaveState)} is called.
 * 	<LI>...user uses Ghidra...
 * 		<UL>
 * 			<LI>Your Plugin's {@link #processEvent(PluginEvent)} is called for events.
 * 			<LI>Your Plugin's Action's methods (ie.
 * 			{@link DockingAction#actionPerformed(docking.ActionContext) actionPerformed}) are called.
 * 			<LI>Your Plugin's published service methods are called by other Plugins.
 * 			<LI>Your Plugin's listener methods are called.
 * 		</UL>
 * 	<LI>Plugin is unloaded due to shutdown of the Tool or being disabled by user
 * 		<OL>
 *			<LI>Your Plugin's {@link #writeConfigState(SaveState)} is called - override this
 *			method to write configuration info into the Tool definition.
 * 			<LI>Your Plugin's {@link #dispose()} is called - override this method to free
 * 			any resources and perform any needed cleanup.
 * 			<LI>Your Plugin's services and events are de-registered automatically.
 * 		</OL>
 * </OL>
 *
 * <h2>Plugin Service dependency</h2>
 * All Plugins must be tagged with a {@link PluginInfo @PluginInfo(...)} annotation.
 * <p>
 * The annotation gives you the ability to declare a dependency on another Plugin
 * via the {@link PluginInfo#servicesRequired() servicesRequired}
 * <p>
 * Ghidra will ensure that your Plugin will not be {@link #init() initialized} until all
 * of its required services are loaded successfully and are available for use when your Plugin
 * calls the {@link PluginTool#getService(Class)} method.
 * <p>
 * Conversely, any services your Plugin advertises in &#64;PluginInfo must be published via calls to
 * {@link #registerServiceProvided(Class, Object) registerServiceProvided()} in your Plugin's 
 * constructor.
 * <p>
 * <b>Cyclic dependencies</b> are not allowed and will cause the Plugin management code to fail to 
 * load your Plugin. (ie. PluginA requires a service that PluginB provides, which requires a service
 * that PluginA provides)
 *
 * <h2>Plugin Service implementation</h2>
 * A Plugin may provide a service to other Plugins by advertising in its {@link PluginInfo}
 * annotation that it {@link PluginInfo#servicesProvided() provides} an interface class.
 * <p>
 * Your Plugin can either directly implement the interface in your Plugin class:
 * <p>
 * &nbsp;&nbsp;<code>public class MyPlugin extends Plugin <b>implements MyService</b> {....}</code>
 * <p>
 * or it may delegate the handling of the service interface to another object during its
 * constructor:
 * <p>
 * &nbsp;&nbsp;<code>public MyPlugin(PluginTool tool) {</code><br>
 * &nbsp;&nbsp;&nbsp;&nbsp;<code>...</code><br>
 * &nbsp;&nbsp;&nbsp;&nbsp;<code>MyService serviceObj = new MyService() { ... };</code><br>
 * &nbsp;&nbsp;&nbsp;&nbsp;<code><b>registerServiceProvided(MyService.class, serviceObj);</b>
 * </code><br>
 * &nbsp;&nbsp;<code>}</code><br>
 * <p>
 * When your Plugin directly implements the advertised service interface, you should <b>not</b>
 * call {@link #registerServiceProvided(Class, Object) registerServiceProvided} for that service
 * interface.
 * <p>
 * Service interface classes are just normal java interface declarations and have no
 * preconditions or other requirements to be used as a Plugin's advertised service interface.
 * <p>
 * Optionally, service interface classes can be marked with meta-data via a
 * {@link ServiceInfo @ServiceInfo} annotation that can have a
 * {@link ServiceInfo#defaultProvider() defaultProvider} property which specifies a Plugin's
 * class (or classname) that should be auto-loaded to provide an implementation of the service
 * interface when that service is required by some other Plugin.  Without the defaultProvider
 * information, dependent Plugins will fail to load unless the user manually loads a Plugin
 * that provides the necessary interface service.
 * <p>
 * Multiple Plugins can implement the same service interface.  Plugins that use that
 * multi-implemented service will either receive a randomly picked instance if using
 * {@link PluginTool#getService(Class)} or will receive all implementations if using
 * {@link PluginTool#getServices(Class)}.
 * <p>
 *
 * <h2>Plugin Events</h2>
 * <UL>
 * 	<LI>Every type of plugin event should be represented by some class extending {@link PluginEvent}.
 *  <LI>One PluginEvent subclass may be used for more than one event type as long as there's some 
 *  natural grouping.
 * </UL>
 *
 * <h2>Component Providers</h2>
 * <UL>
 *  <LI>A plugin may supply a {@link ComponentProvider} that provides a visual component when 
 *  the plugin is added to the tool.
 * </UL>
 *
 * <h2>Important interfaces Plugins often need to implement</h2>
 * <UL>
 * 	<LI>{@link OptionsChangeListener} - to receive notification when a configuration option
 * 	is changed by the user.
 * 	<LI>{@link FrontEndable} - marks this Plugin as being suitable for inclusion in the FrontEnd 
 * 		tool.
 * 	<LI>{@link FrontEndOnly} - marks this Plugin as FrontEnd only, not usable in CodeBrowser or 
 * 		other tools.
 * 	<LI>{@link ProgramaticUseOnly} - marks this Plugin as special and not for user configuration.
 * </UL>
 *
 */
public abstract class Plugin implements ExtensionPoint, PluginEventListener, ServiceListener {

	/**
	 * The {@link PluginTool} that hosts/contains this Plugin.
	 */
	protected PluginTool tool;

	/**
	 * Name of this plugin, derived from the simple class name.
	 */
	protected final String name = PluginUtils.getPluginNameFromClass(getClass());

	/**
	 * Static information about this Plugin, derived from its {@link PluginInfo} annotation.
	 */
	protected final PluginDescription pluginDescription =
		PluginDescription.getPluginDescription(getClass());

	/**
	 * Temporary compatibility for Plugins that have not been updated to new PluginInfo API.
	 * <p>
	 * Contains the list of service classes that this plugin registered as being required.
	 * <p>
	 * Ignored if the PluginDescription has values for requiredServices.
	 */
	private List<Class<?>> legacyRequiredServices = new ArrayList<>();

	private List<Class<? extends PluginEvent>> eventsProduced = new ArrayList<>();
	private List<Class<? extends PluginEvent>> eventsConsumed = new ArrayList<>();
	private List<ServiceInterfaceImplementationPair> services = new ArrayList<>();

	/**
	 * Flag that indicates that this Plugin's constructor phase has finished.  Used to
	 * decide if events or services should be directly registered with the Tool or if they
	 * should be queued to be registered later.
	 */
	private boolean constructorFinished = false;

	private boolean disposed = false;

	/**
	 * Construct a new Plugin.
	 * <p>
	 * @param tool PluginTool that will host/contain this plugin.
	 */
	protected Plugin(PluginTool tool) {
		this.tool = tool;
		tool.addServiceListener(this);

		registerPluginImplementedServices();
		registerStaticEvents();
	}

	/**
	 * Construct a new Plugin.
	 * <p>
	 * Deprecated, use {@link Plugin#Plugin(PluginTool)} instead.
	 *
	 * @param pluginName name of plugin - not used.
	 * @param tool tool that will contain this plugin
	 */
	@Deprecated
	protected Plugin(String pluginName, PluginTool tool) {
		this(tool);
	}

	/**
	 * Auto-registers any services directly implemented by this Plugin instance (ie.
	 * the MyService in "class MyPlugin extends Plugin implements MyService { }" )
	 */
	private void registerPluginImplementedServices() {
		for (Class<?> serviceClass : pluginDescription.getServicesProvided()) {
			if (serviceClass.isInstance(this)) {
				doRegisterServiceProvided(serviceClass, this, false);
			}
		}
	}

	/**
	 * Auto-registers any PluginEvents listed in the Plugin's description.
	 */
	private void registerStaticEvents() {
		for (Class<? extends PluginEvent> eventClass : pluginDescription.getEventsProduced()) {
			eventsProduced.add(eventClass);
			tool.registerEventProduced(eventClass);
		}
		for (Class<? extends PluginEvent> eventClass : pluginDescription.getEventsConsumed()) {
			eventsConsumed.add(eventClass);
			tool.addEventListener(eventClass, this);
		}
	}

	/**
	 * Returns plugin name or null if given class does not extend {@link Plugin}
	 * <p>
	 * Deprecated, use {@link PluginUtils#getPluginNameFromClass(Class)}
	 * <p>
	 * @param pluginClass the plugin class
	 * @return the plugin name
	 */
	@Deprecated
	public static String getPluginName(Class<?> pluginClass) {
		if (pluginClass != Plugin.class && Plugin.class.isAssignableFrom(pluginClass)) {
			return pluginClass.getSimpleName();
		}
		return null;
	}

	protected void cleanup() {
		if (!disposed) {
			Throwable thr = null;
			try {
				disposed = true;
				dispose();
			}
			catch (Throwable t) {
				thr = t;
			}
			tool.removeServiceListener(this);
			legacyRequiredServices.clear();
			unregisterServices();
			unregisterEvents();
			tool.removeAll(getName());
			tool = null;
			if (thr != null) {
				throw new RuntimeException(thr);
			}
		}
	}

	/**
	 * Returns this plugin's name.
	 * <p>
	 * @return String name, derived from simple class name.
	 */
	public final String getName() {
		return name;
	}

	@Override
	public final void eventSent(PluginEvent event) {
		if (!SystemUtilities.isEqual(event.getSourceName(), getName())) {
			processEvent(event);
		}
	}

	/**
	 * Method called to process a plugin event.  Plugins should override this method
	 * if the plugin processes PluginEvents;
	 * @param event plugin to process
	 */
	public void processEvent(PluginEvent event) {
		// do nothing by default; subclasses should override as needed
	}

	/**
	 * Get the {@link PluginTool} that hosts/contains this plugin.
	 *
	 * @return PluginTool
	 */
	public final PluginTool getTool() {
		return tool;
	}

	/**
	 * Return classes of data types that this plugin can support.
	 * <p>
	 * @return classes of data types that this plugin can support
	 */
	public Class<?>[] getSupportedDataTypes() {
		return new Class[0];
	}

	/**
	 * Method called if the plugin supports this domain file.
	 * <p>
	 * @param data array of {@link DomainFile}s
	 * @return boolean true if can accept
	 */
	public boolean acceptData(DomainFile[] data) {
		return false;
	}

	/**
	 * Get the domain files that this plugin has open.
	 * <p>
	 * @return array of {@link DomainFile}s that are open by this Plugin.
	 */
	public DomainFile[] getData() {
		return new DomainFile[] {};
	}

	/**
	 * Called after the constructor and before {@link #init()} to publish services to 
	 * the Tool's service registry.
	 * <p>
	 * Services registered during the constructor call will be queued in the services list.
	 * This method will register those early services with the Tool, and henceforth,
	 * new services will be directly registered with the Tool.
	 */
	final void initServices() {
		constructorFinished = true;
		registerQueuedServices();
	}

	@SuppressWarnings("unchecked")
	private void registerQueuedServices() {
		// Dealing with Class<?> and its matching impl makes us do the casting that
		// triggers the warning.
		Set<Class<?>> publishedServices = new HashSet<>(pluginDescription.getServicesProvided());
		for (ServiceInterfaceImplementationPair siip : services) {
			tool.addService((Class<Object>) siip.interfaceClass, siip.provider);
			publishedServices.remove(siip.interfaceClass);
		}
		for (Class<?> c : publishedServices) {
			Msg.warn(this, "Plugin " + getName() + " did not register a service handler for: " + c);
		}
	}

	void processLastEvents(PluginEvent[] lastEvents) {
		for (PluginEvent lastEvent : lastEvents) {
			try {
				if (eventsConsumed.contains(lastEvent.getClass())) {
					processEvent(lastEvent);
				}
			}
			catch (Throwable t) {
				Msg.debug(this, "Unexpected exception processing plugin event", t);
			}
		}
	}

	/**
	 * Initialization method; override to add initialization for this plugin.
	 * This is where a plugin should acquire its services. When this method
	 * is called, all plugins have been instantiated in the tool.
	 */
	protected void init() {
		// do nothing by default; subclasses should override as needed
	}

	/**
	 * Tells a plugin that it is no longer needed.  The plugin should release
	 * any resources that it has.  All actions, components, services will automatically
	 * be cleaned up.
	 */
	protected void dispose() {
		// do nothing by default; subclasses should override as needed
	}

	/**
	 * Tells the Plugin to read its data-independent (preferences)
	 * properties from the input stream.
	 * @param saveState object that holds primitives for state information
	 */
	public void readConfigState(SaveState saveState) {
		// do nothing by default; subclasses should override as needed
	}

	/**
	 * Tells a Plugin to write any data-independent (preferences)
	 * properties to the output stream.
	 * @param saveState object that holds primitives for state information
	 */
	public void writeConfigState(SaveState saveState) {
		// do nothing by default; subclasses should override as needed
	}

	/**
	 * Tells the Plugin to write any data-dependent state to the
	 * output stream.
	 * @param saveState object that holds primitives for state information
	 */
	public void writeDataState(SaveState saveState) {
		// do nothing by default; subclasses should override as needed
	}

	/**
	 * Tells the Plugin to read its data-dependent state from the
	 * given SaveState object.
	 * @param saveState object that holds primitives for state information
	 */
	public void readDataState(SaveState saveState) {
		// do nothing by default; subclasses should override as needed
	}

	/**
	 * Fire the given plugin event; the tool notifies all other plugins
	 * who are interested in receiving the given event type.
	 * @param event event to fire
	 */
	public void firePluginEvent(PluginEvent event) {
		if (tool != null) {
			event.setSourceName(getName());
			tool.firePluginEvent(event);
		}
	}

	Class<?>[] getServiceClasses() {
		Class<?>[] classes = new Class[services.size()];
		for (int i = 0; i < classes.length; i++) {
			classes[i] = (services.get(i)).interfaceClass;
		}
		return classes;
	}

	/**
	 * Notifies this plugin that a service has been added to
	 *   the plugin tool.
	 * Plugins should override this method if they update their state
	 * when a particular service is added.
	 *
	 * @param interfaceClass The <b>interface</b> of the added service
	 * @param service service that is being added
	 */
	@Override
	public void serviceAdded(Class<?> interfaceClass, Object service) {
		// do nothing by default; subclasses should override as needed
	}

	/**
	 * Notifies this plugin that service has been removed from the
	 *   plugin tool.
	 * Plugins should override this method if they update their state
	 * when a particular service is removed.
	 *
	 * @param interfaceClass The <b>interface</b> of the added service
	 * @param service that is being removed.
	 */
	@Override
	public void serviceRemoved(Class<?> interfaceClass, Object service) {
		// do nothing by default; subclasses should override as needed
	}

	/**
	 * Check if this plugin depends on the given plugin
	 * 
	 * @param plugin the plugin
	 * @return true if this plugin depends on the given plugin
	 */
	public boolean dependsUpon(Plugin plugin) {
		for (Class<?> c : getList(pluginDescription.getServicesRequired(),
			legacyRequiredServices)) {
			// If one of our required services is provided by a single Plugin,
			// then we depend on that Plugin.  If multiple provide, we are not dependent.
			if (plugin.isOnlyProviderOfService(c)) {
				return true;
			}
		}
		return false;
	}

	public List<Class<?>> getMissingRequiredServices() {
		List<Class<?>> missingServices = new ArrayList<>();
		for (Class<?> requiredServiceClass : getList(pluginDescription.getServicesRequired(),
			legacyRequiredServices)) {
			if (tool.getService(requiredServiceClass) == null) {
				missingServices.add(requiredServiceClass);
			}
		}
		return missingServices;
	}

	/**
	 * Checks if this plugin is missing a required service.
	 *
	 * @return boolean true if a required service isn't available via the PluginTool.
	 */
	public boolean hasMissingRequiredService() {
		for (Class<?> depClass : getList(pluginDescription.getServicesRequired(),
			legacyRequiredServices)) {
			if (tool.getService(depClass) == null) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Used to choose between lists to support the old Plugin ABI backward compatible lists
	 *
	 * @param l1 the new list from the static PluginDescription config - preferred if it has any elements
	 * @param l2 the old list - only returned if l1 is empty
	 * @return either l1 or l2, depending on which one has elements.
	 */
	private static <T> List<T> getList(List<T> l1, List<T> l2) {
		return !l1.isEmpty() ? l1 : l2;
	}

	/**
	 * Register event that this plugin produces.
	 * <p>
	 * Deprecated, use {@link PluginInfo @PluginInfo.eventsProduced} instead.
	 * <p>
	 * @param eventClass Class of the produced event; class is required to force it
	 * to be loaded
	 */
	@Deprecated
	protected final void registerEventProduced(Class<? extends PluginEvent> eventClass) {
		eventsProduced.add(eventClass);
		tool.registerEventProduced(eventClass);
	}

	private void unregisterEvents() {
		for (Class<? extends PluginEvent> c : eventsConsumed) {
			tool.removeEventListener(c, this);
		}
		for (Class<? extends PluginEvent> c : eventsProduced) {
			tool.unregisterEventProduced(c);
		}
	}

	/**
	 * Register event that this plugin consumes.
	 * <p>
	 * Deprecated, use {@link PluginInfo @PluginInfo.eventsConsumed} instead.
	 * <p>
	 * @param eventClass Class for the event; class is required to force it
	 * to be loaded
	 */
	@Deprecated
	protected final void registerEventConsumed(Class<? extends PluginEvent> eventClass) {
		registerDynamicEventConsumed(eventClass);
	}

	/**
	 * Register event that this plugin consumes.
	 * <p>
	 * @param eventClass Class for the event; class is required to force it
	 * to be loaded
	 */
	protected final void registerDynamicEventConsumed(Class<? extends PluginEvent> eventClass) {
		eventsConsumed.add(eventClass);
		tool.addEventListener(eventClass, this);
	}

	/**
	 * Registers a service.
	 * <p>
	 * If the constructor isn't finished yet (constructorFinished == false), the service is
	 * just queued up in the services list.
	 * <p>
	 * If the constructor is finished, the service is added to the services list and registered
	 * with the PluginTool's services.
	 * <p>
	 * The {@link #initServices()} handles registering the services queued during the constructor.
	 * <p>
	 * @param interfaceClass Class that the service object implements.
	 * @param service Service object instance.
	 * @param dynamicRegister boolean flag that indicates that the service being registered
	 * is being registered during the 'static' initialization phase (using information from
	 * the static {@link PluginDescription}) or in a dynamic manner during runtime.
	 */
	@SuppressWarnings("unchecked")
	private void doRegisterServiceProvided(Class<?> interfaceClass, Object service,
			boolean dynamicRegister) {
		Objects.requireNonNull(service,
			"Service instance can not be null! Interface: " + interfaceClass.getName());
//		#if ( can_do_strict_checking_of_service_registration )
//		if (constructorFinished && !dynamicRegister) {
//			throw new IllegalArgumentException(
//				"Services must be registered during Plugin constructor: " + interfaceClass + ", " +
//					getName());
//		}
//		#endif
		if (!pluginDescription.getServicesProvided().contains(interfaceClass)) {
//		#if ( can_do_strict_checking_of_service_registration )
//			throw new IllegalArgumentException(
//				"Services must be advertised in PluginInfo annotation: " + interfaceClass + ", " +
//					getName());
//		#else
			Msg.warn(this, "Services must be advertised in @PluginInfo annotation - service " +
				interfaceClass + "; from plugin " + getName());
//		#endif
		}
		services.add(new ServiceInterfaceImplementationPair(interfaceClass, service));
		if (constructorFinished) {
			tool.addService((Class<Object>) interfaceClass, service);
		}
	}

	/**
	 * Used to register a service (that has already been announced in this Plugin's
	 * PluginInfo annotation via
	 * {@link PluginInfo#servicesProvided() servicesProvided = SomeService.class}) during the
	 * Plugin's constructor phase, IFF the service is implemented by an object other
	 * than the Plugin instance itself.
	 * <p>
	 * Do not use this to register a service if your Plugin class implements that
	 * service's interface because your Plugin will have been automatically registered as
	 * providing that service.
	 * <p>
	 * If you need to register a service after the constructor is finished, use
	 * {@link #registerDynamicServiceProvided(Class, Object)}.
	 * <p>
	 * Using this method outside of your constructor will (someday) throw an IllegalArgumentException.
	 *
	 * @param interfaceClass service interface class
	 * @param service service implementation
	 */
	protected final <T> void registerServiceProvided(Class<? super T> interfaceClass, T service) {
		doRegisterServiceProvided(interfaceClass, service, false);
	}

	/**
	 * Used to register a service dynamically, during runtime, instead of during the Plugin's
	 * constructor.
	 * <p>
	 * @param interfaceClass service interface class
	 * @param service service implementation
	 */
	protected final <T> void registerDynamicServiceProvided(Class<? super T> interfaceClass,
			T service) {
		doRegisterServiceProvided(interfaceClass, service, true);
	}

	/**
	 * Returns the combination of required and non-required used services.
	 *
	 * @return union of the lists of required and non-required used services.
	 */
	protected final List<Class<?>> getServicesRequired() {
		// return either the new PluginDescription servicesRequired or the old
		// deprecated legacyRequiredServices.
		return getList(pluginDescription.getServicesRequired(), legacyRequiredServices);
	}

	private void unregisterServices() {
		for (ServiceInterfaceImplementationPair siip : services) {
			tool.removeService(siip.interfaceClass, siip.provider);
		}
	}

	/**
	 * Registers a dependency on a service interface Class.
	 * <p>
	 * This method is deprecated.  Use {@link PluginInfo#servicesRequired() @PluginInfo.servicesRequired}
	 * instead.
	 * <p>
	 * @param interfaceClass interface class that this plugin depends on
	 * @param isDependency boolean flag, if true this plugin will not work without the
	 * specified service, if false this service can work without it.  If false, this
	 * method is a no-op as non-dependency registration information is now discarded.
	 */
	@Deprecated
	protected final void registerServiceUsed(Class<?> interfaceClass, boolean isDependency) {
		if (isDependency) {
			legacyRequiredServices.add(interfaceClass);
		}
		// information about non-dependency used-services is discarded.  Only
		// required services are retained.
	}

	protected final void deregisterService(Class<?> interfaceClass, Object service) {

		for (int i = 0; i < services.size(); i++) {
			ServiceInterfaceImplementationPair s = services.get(i);
			if (s.interfaceClass == interfaceClass && s.provider == service) {
				tool.removeService(interfaceClass, service);
				services.remove(i);
				break;
			}
		}
	}

	boolean providesService(Class<?> interfaceClass) {
		for (ServiceInterfaceImplementationPair siip : services) {
			if (siip.interfaceClass == interfaceClass) {
				return true;
			}
		}
		return false;
	}

	List<Object> getServiceProviderInstances(Class<?> interfaceClass) {
		List<Object> providerInstances = new ArrayList<>();

		for (ServiceInterfaceImplementationPair myService : services) {
			if (myService.interfaceClass == interfaceClass) {
				providerInstances.add(myService.provider);
			}
		}
		return providerInstances;
	}

	private boolean isOnlyProviderOfService(Class<?> serviceClass) {
		// Returns true if this Plugin instance is the only active plugin that provides
		// the specified service.

		if (tool == null) {
			return false;
		}
		Object[] activeServiceInstances = tool.getServices(serviceClass);
		int count = 0;
		for (ServiceInterfaceImplementationPair myService : services) {
			if (myService.interfaceClass == serviceClass) {
				count++;
			}
		}
		// if count == activeServiceInstances.length, then we are the one providing the service
		return activeServiceInstances.length != 0 && activeServiceInstances.length == count;
	}

	/**
	 * Called to force this plugin to terminate any tasks it has running and
	 * apply any unsaved data to domain objects or files. If it can't do
	 * this or the user cancels then this returns false.
	 * @return true if this plugin can close.
	 */
	protected boolean canClose() {
		return true;
	}

	/**
	 * Override this method if the plugin needs to cancel the closing of the domain object
	 * @param dObj the domain object
	 * @return false if the domain object should NOT be closed
	 */
	protected boolean canCloseDomainObject(DomainObject dObj) {
		return true;
	}

	/**
	 * Called to allow this plugin to flush any caches to the domain object before it is
	 * saved.
	 * @param dObj domain object about to be saved
	 */
	protected void prepareToSave(DomainObject dObj) {
		// do nothing by default; subclasses should override as needed
	}

	/**
	 * Called to force this plugin to save any domain object data it is controlling.
	 * @return false if this plugin controls a domain object, but couldn't
	 * save its data or the user canceled the save.
	 */
	protected boolean saveData() {
		return true;
	}

	/**
	 * Returns true if this plugin has data that needs saving;
	 * @return true if this plugin has data that needs saving;
	 */
	protected boolean hasUnsaveData() {
		return false;
	}

	/**
	 * Close the plugin.   This is when the plugin should release resources, such as those from
	 * other services.  This method should not close resources being used by others (that should
	 * happen in dispose()).
	 * 
	 * <p>This method will be called before {@link #dispose()}.
	 */
	protected void close() {
		// do nothing by default; subclasses should override as needed
	}

	public boolean isDisposed() {
		return disposed;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof Plugin)) {
			return false;
		}
		Plugin plugin = (Plugin) obj;
		if (tool != plugin.tool) {
			return false;
		}
		return plugin.name.equals(name);
	}

	@Override
	public int hashCode() {
		return name.hashCode();
	}

	/**
	 * Provides the transient state object that was returned in the corresponding getTransientState()
	 * call.  Plugins should override this method if they have state that needs to be saved as domain objects
	 * get switched between active and inactive.
	 * @param state the state object that was generated by this plugin's getTransientState() method.
	 */
	public void restoreTransientState(Object state) {
		// do nothing by default; subclasses should override as needed
	}

	/**
	 * Returns an object containing the plugins state.  Plugins should override this method if
	 * they have state that they want to maintain between domain object state transitions (i.e. when the
	 * user tabs to a different domain object and back) Whatever object is returned will be fed back to
	 * the plugin after the tool state is switch back to the domain object that was active when the this
	 * method was called.
	 * @return Object to be return in the restoreTransientState() method.
	 */
	public Object getTransientState() {
		return null;
	}

	/**
	 * Notification that all plugins have had their data states restored.
	 */
	public void dataStateRestoreCompleted() {
		// do nothing by default; subclasses should override as needed
	}

	/**
	 * Returns an object containing the plugin's state as needed to restore itself after an undo
	 * or redo operation.  Plugins should override this method if they have special undo/redo handling.
	 * @param domainObject the object that is about to or has had undoable changes made to it.
	 * @return the state object
	 */
	public Object getUndoRedoState(DomainObject domainObject) {
		// do nothing by default; subclasses should override as needed
		return null;
	}

	/**
	 * Updates the plugin's state based on the data stored in the state object.  The state object
	 * is the object that was returned by this plugin in the {@link #getUndoRedoState(DomainObject)}
	 * @param domainObject the domain object that has had an undo or redo operation applied to it.
	 * @param state the state that was recorded before the undo or redo operation.
	 */
	public void restoreUndoRedoState(DomainObject domainObject, Object state) {
		// do nothing by default; subclasses should override as needed
	}

	/**
	 * Returns the static {@link PluginDescription} object that was derived from the
	 * {@link PluginInfo @PluginInfo} annotation at the top of your Plugin.
	 * <p>
	 * @return the static/shared {@link PluginDescription} instance that describes this Plugin.
	 */
	public final PluginDescription getPluginDescription() {
		return pluginDescription;
	}

}
