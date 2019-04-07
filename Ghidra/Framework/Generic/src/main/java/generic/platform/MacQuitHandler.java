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
 * A base implementation for creating an 'Quit' menu action callback.  This is executed when
 * the user presses the Dock's 'Ghidra->Quit' menu action.
 * <p>
 * Simply constructing this class will register it.
 * <p>
 * See 
 * com.apple.eawt.Application.setQuitHandler(QuitHandler)
 * com.apple.eawt.AboutHandler.handleQuitRequestWith(QuitEvent, QuitResponse)
 */
public abstract class MacQuitHandler extends AbstractMacHandler {

	public MacQuitHandler() {
		addQuitApplicationListener(this);
	}

	public abstract void quit();

	private void addQuitApplicationListener(MacQuitHandler macQuitHandler) {
		if (Platform.CURRENT_PLATFORM.getOperatingSystem() != OperatingSystem.MAC_OS_X) {
			return;
		}

		try {
			Object application = getApplication();
			setQuitHandler(application);
		}
		catch (Exception e) {
			Msg.error(this, "Unable to install Mac quit handler", e);
		}
	}

	private void setQuitHandler(Object application) throws Exception {

		Class<?> quitHandlerClass = Class.forName("com.apple.eawt.QuitHandler");
		Object quitHandler = Proxy.newProxyInstance(getClass().getClassLoader(),
			new Class[] { quitHandlerClass }, this);
		MethodUtils.invokeMethod(application, "setQuitHandler", quitHandler);
	}

	@Override
	public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {

		// Args: QuitEvent event, QuitResponse response

		// Call QuitResponse.cancelQuit(), as we will allow our tool to quit the application
		// instead of the OS.
		Object response = args[1];
		MethodUtils.invokeExactMethod(response, "cancelQuit");

		quit();

		// the handleQuitRequestWith() is void--return null
		return null;
	}

}
