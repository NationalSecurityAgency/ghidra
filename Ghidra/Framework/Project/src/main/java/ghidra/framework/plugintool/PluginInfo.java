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

import java.lang.annotation.*;

import ghidra.framework.plugintool.util.PluginStatus;

/**
 * Information about a Ghidra {@link Plugin}.
 * <p>
 * Example:
 * <pre>
 * &#64;PluginInfo(
 * 	status = PluginStatus.RELEASED,
 * 	packageName = CorePluginPackage.NAME,
 * 	category = PluginCategoryNames.COMMON,
 * 	shortDescription = "Short description of plugin",
 * 	description = "Longer description of plugin.",
 * 	servicesProvided = { ServiceInterfaceThisPluginProvides.class }
 * 	servicesRequired = { RequiredServiceInterface1.class, RequiredServiceInterface2.class },
 * 	eventsConsumed = { SomePluginEvent.class },
 * 	eventsProduced = { AnotherPluginEvent.class },
 * 	isSlowInstallation = false
 * )
 * </pre>
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface PluginInfo {
	/**
	 * The {@link PluginStatus} of this plugin:
	 * {@link PluginStatus#STABLE STABLE} , {@link PluginStatus#RELEASED RELEASED},
	 * {@link PluginStatus#HIDDEN HIDDEN}, {@link PluginStatus#UNSTABLE UNSTABLE}
	 * <p>
	 * @return {@link PluginStatus#STABLE STABLE} , {@link PluginStatus#RELEASED RELEASED},
	 * {@link PluginStatus#HIDDEN HIDDEN}, {@link PluginStatus#UNSTABLE UNSTABLE}, etc.
	 */
	PluginStatus status();

	/**
	 * The package name this plugin belongs in.
	 * <p>
	 * Use XYZPluginPackage.NAME
	 * <p>
	 * @return String package name
	 */
	String packageName();

	/**
	 * See PluginCategoryNames
	 * <p>
	 * <ul>
	 * <li>PluginCategoryNames.COMMON
	 * <li>PluginCategoryNames.SUPPORT
	 * <li>PluginCategoryNames.etc
	 * </ul>
	 * @return String category
	 */
	String category();

	/**
	 * A brief description of what the plugin does.
	 * <p>
	 * This string probably should not end with a "." character.
	 *
	 * @return String brief description of what the plugin does.
	 */
	String shortDescription();

	/**
	 * The long description of what the plugin does.
	 * <p>
	 * This string probably should end with a "." character.
	 *
	 * @return String description of what the plugin does
	 */
	String description();

	/**
	 * Signals that this plugin loads slowly.
	 *
	 * @return boolean
	 */
	boolean isSlowInstallation() default false;

	/**
	 * List of PluginEvents (classes) that this Plugin consumes.
	 *
	 * @return PluginEvent class list, defaults to empty.
	 */
	Class<? extends PluginEvent>[] eventsConsumed() default {};

	/**
	 * List of PluginEvent (classes) that this Plugin produces.
	 *
	 * @return PluginEvent class list, defaults to emtpy.
	 */
	Class<? extends PluginEvent>[] eventsProduced() default {};

	/**
	 * List of service interface Classes that this Plugin requires (depends on).
	 *
	 * @return List of Classes, defaults to empty.
	 */
	Class<?>[] servicesRequired() default {};

	/**
	 * List of service interface Classes that this Plugin provides.
	 *
	 * @return List of Classes, defaults to empty.
	 */
	Class<?>[] servicesProvided() default {};

}
