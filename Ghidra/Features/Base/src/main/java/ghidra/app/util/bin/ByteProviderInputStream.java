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
package ghidra.app.util.bin;

import java.io.IOException;
import java.io.InputStream;

public class ByteProviderInputStream extends InputStream {
	private ByteProvider provider;
	private long offset;
	private long length;
	private long nextOffset;

	public ByteProviderInputStream( ByteProvider provider, long offset, long length ) {
		this.provider = provider;
		this.offset = offset;
		this.length = length;
		this.nextOffset = offset;
	}

	@Override
	public int read() throws IOException {
		if ( nextOffset < offset + length ) {
			return provider.readByte( nextOffset++ ) & 0xff;
		}
		return -1;
	}

}
