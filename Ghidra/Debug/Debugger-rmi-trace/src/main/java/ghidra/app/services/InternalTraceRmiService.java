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
package ghidra.app.services;

import java.io.IOException;
import java.net.SocketAddress;

import ghidra.app.plugin.core.debug.service.tracermi.DefaultTraceRmiAcceptor;
import ghidra.app.plugin.core.debug.service.tracermi.TraceRmiHandler;
import ghidra.debug.spi.tracermi.TraceRmiLaunchOpinion;

/**
 * The same as the {@link TraceRmiService}, but grants access to the internal types (without
 * casting) to implementors of {@link TraceRmiLaunchOpinion}.
 */
public interface InternalTraceRmiService extends TraceRmiService {
	@Override
	DefaultTraceRmiAcceptor acceptOne(SocketAddress address) throws IOException;

	@Override
	TraceRmiHandler connect(SocketAddress address) throws IOException;
}
