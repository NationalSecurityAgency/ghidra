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
package ghidra.app.plugin.core.osgi;

import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;

public abstract class GhidraBundleActivator implements BundleActivator {
	protected abstract void start(BundleContext bundleContext, Object api);

	protected abstract void stop(BundleContext bundleContext, Object api);

	@Override
	public final void start(BundleContext bundleContext) throws Exception {
		start(bundleContext, null);
	}

	@Override
	public final void stop(BundleContext bundleContext) throws Exception {
		stop(bundleContext, null);
	}

}
