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
package ghidra.app.script.osgi;

import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;

public abstract class GhidraBundleActivator implements BundleActivator {
	protected abstract void start(BundleContext bc, Object api);

	protected abstract void stop(BundleContext bc, Object api);

	@Override
	final public void start(BundleContext bc) throws Exception {
		start(bc, null);
	}

	@Override
	final public void stop(BundleContext bc) throws Exception {
		stop(bc, null);
	}

}
