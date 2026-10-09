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
package ghidra.app.plugin.core.bento;

import ghidra.framework.plugintool.ServiceInfo;

/**
 * The BentoService provides a general service for displaying objects (a la Boxes)
 */
@ServiceInfo(defaultProvider = BentoServicePlugin.class, description = "Display X vs. Y data")
public interface BentoService {

	public BentoProvider getDefaultProvider();

	public BentoProvider createProvider();

}
