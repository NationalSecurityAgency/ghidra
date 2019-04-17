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

/**
 * Meta-data about a Plugin's Service.
 * <p>
 * Example:
 * <p>
 * <pre>@ServiceInfo( defaultProvider = MyPlugin.class )
 * public interface MyService {
 *  public void foo();
 *}</pre>
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface ServiceInfo {
	/**
	 * Sets the class name of the class that provides the default implementation of this service.
	 * <p>
	 * Use this form instead of {@link #defaultProvider() defaultProvider = Someclass.class}
	 * if you want to prevent any form of reference between the service class and
	 * the implementation class.
	 * <p>
	 * For example, <code>defaultProviderName = "packageX.subPackageY.SomeClass"</code>
	 * <p>
	 * Using <code>defaultProviderName = packageX.subPackageY.SomeClass.class.getName()</code>
	 * will not work (value needs to be a constant expression).
	 * <p>
	 *
	 * @return full package and classname string of the plugin class that provides this service.
	 */
	String defaultProviderName() default "";

	/**
	 * Sets the class that provides the default implementation of this service.
	 * <p>
	 * @return Class instance of the plugin that provides this service.
	 */
	Class<? extends Plugin>[] defaultProvider() default {};

	/**
	 * Sets the description for this service.
	 * <p>
	 * Currently not used.
	 *
	 * @return string description of this service.
	 */
	String description() default "";
}
