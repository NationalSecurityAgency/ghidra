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
package generic.platform;

import java.lang.reflect.InvocationHandler;

import org.apache.commons.lang3.reflect.MethodUtils;

/**
 * A general interface for handle Mac Application callbacks.  Some possible callbacks are:
 * <ul>
 * 	<li>quit</li>
 * 	<li>about</li>
 * 	<li>preferences</li>
 * 	<li>file handling</li>
 * </ul>
 * 
 * see com.apple.eawt.Application
 */
abstract class AbstractMacHandler implements InvocationHandler {



	protected Object getApplication() throws Exception {
		Class<?> clazz = Class.forName("com.apple.eawt.Application");
		Object application = MethodUtils.invokeExactStaticMethod(clazz, "getApplication");
		return application;
	}

}
