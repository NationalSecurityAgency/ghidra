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
package ghidra.framework.protocol.ghidra;

import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;

import org.osgi.service.url.AbstractURLStreamHandlerService;

/**
 * {@link GhidraOSGIStreamHandler} provides a Ghidra URL stream handler service for 
 * Felix OSGI.  This allows direct use of the standard {@code ghidra} protocol 
 * {@link Handler} and bypasses the improper IOException propagation caused by
 * {@code URLHandlersStreamHandlerProxy.openConnection(URL)}.
 */
public class GhidraOSGIStreamHandler extends AbstractURLStreamHandlerService {

	private static final Handler ghidraProtocolHandler = new Handler();

	@Override
    public URLConnection openConnection(URL url) throws IOException {
		return ghidraProtocolHandler.openConnection(url);
    }

	@Override
	public int getDefaultPort() {
		return ghidraProtocolHandler.getDefaultPort();
	}
}
