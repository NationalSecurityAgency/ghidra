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
package ghidra.app.plugin.core.debug.service.control;

import java.io.IOException;

import db.Transaction;
import ghidra.trace.model.guest.TraceGuestPlatform;
import ghidra.trace.model.guest.TracePlatform;

public class DebuggerControlServiceGuestTest extends DebuggerControlServiceTest {
	protected TraceGuestPlatform platform;

	public void createToyPlatform() {
		try (Transaction tx = tb.startTransaction()) {
			platform = tb.trace.getPlatformManager()
					.addGuestPlatform(getToyBE64Language().getDefaultCompilerSpec());
			platform.addMappedRegisterRange();
			platform.addMappedRange(tb.addr(0), tb.addr(platform, 0), -1);
		}
		catch (Exception e) {
			throw new AssertionError(e);
		}
	}

	@Override
	protected void createAndOpenTrace() throws IOException {
		createAndOpenTrace("DATA:BE:64:default");
		createToyPlatform();
	}

	@Override
	protected void activateTrace() {
		traceManager.activatePlatform(platform);
	}

	@Override
	protected TracePlatform getPlatform() {
		return platform;
	}
}
