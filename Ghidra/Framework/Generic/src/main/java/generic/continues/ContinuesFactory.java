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
package generic.continues;

import java.lang.reflect.Constructor;

import net.sf.cglib.proxy.Enhancer;

public class ContinuesFactory implements GenericFactory {

	private static final boolean enabled = Boolean.getBoolean("ContinuesInterceptor.enabled");

	private ExceptionHandler exceptionHandler;

	public ContinuesFactory(ExceptionHandler exceptionHandler) {
		if (exceptionHandler == null) {
			throw new IllegalArgumentException("exceptionHandler == null not allowed");
		}
		this.exceptionHandler = exceptionHandler;
	}

	@Override
	public Object create(Class<?> type, Object... args) {
		try {
			Object thing;
			if (!enabled) {
				Constructor<?> c = type.getConstructor(new Class<?>[0]);
				thing = c.newInstance(args);
			}
			else {
				ContinuesInterceptor interceptor = new ContinuesInterceptor(exceptionHandler);
				Enhancer e = new Enhancer();
				e.setSuperclass(type);
				e.setCallback(interceptor);
				thing = e.create();
			}
			return thing;
		}
		catch (Throwable e) {
			try {
				exceptionHandler.handle(e);
			}
			catch (Throwable t) {
				// let the handler supplant the original exception if need be
				e = t;
			}
			// wrap so clients don't need try/catch everywhere
			throw new RuntimeException(e);
		}
	}
}
