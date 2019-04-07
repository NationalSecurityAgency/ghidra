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

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

import org.apache.commons.lang3.reflect.MethodUtils;

import ghidra.framework.OperatingSystem;
import ghidra.framework.Platform;
import ghidra.util.Msg;

/**
 * A base implementation for creating an 'About' menu action callback.  This is executed when
 * the user presses the Dock's 'Ghidra->About' menu action.
 * <p>
 * Simply constructing this class will register it.
 * <p>
 * See 
 * com.apple.eawt.Application.setAboutHandler(AboutHandler)
 * com.apple.eawt.AboutHandler.handleAbout(AboutEvent)
 */
public abstract class MacAboutHandler extends AbstractMacHandler {

	public MacAboutHandler() {
		addAboutApplicationListener();
	}

	public abstract void about();

	private void addAboutApplicationListener() {
		if (Platform.CURRENT_PLATFORM.getOperatingSystem() != OperatingSystem.MAC_OS_X) {
			return;
		}

		try {
			Object application = getApplication();
			setAboutHandler(application);
		}
		catch (Exception e) {
			Msg.error(this, "Unable to install Mac quit handler", e);
		}
	}

	private void setAboutHandler(Object application) throws Exception {

		Class<?> aboutHandlerClass = Class.forName("com.apple.eawt.AboutHandler");
		Object aboutHandler = Proxy.newProxyInstance(getClass().getClassLoader(),
			new Class[] { aboutHandlerClass }, this);
		MethodUtils.invokeMethod(application, "setAboutHandler", aboutHandler);
	}

	@Override
	public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {

		// Args: AboutEvent

		about(); // call our about() callback, ignoring the Application API

		// the handleAbout() is void--return null
		return null;
	}
}
