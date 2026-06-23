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
package ghidra.app.plugin.core.terminal.vt;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;

import ghidra.util.Msg;

public abstract class VtResponseEncoder {
	protected static final byte[] PASTE_START = VtHandler.ascii("\033[200~");
	protected static final byte[] PASTE_END = VtHandler.ascii("\033[201~");
	protected static final byte[] THEME_DARK_MODE = VtHandler.ascii("\033[?997;1n");
	protected static final byte[] THEME_LIGHT_MODE = VtHandler.ascii("\033[?997;2n");

	protected ByteBuffer bb = ByteBuffer.allocate(16);

	protected final Charset charset;

	public VtResponseEncoder(Charset charset) {
		this.charset = charset;
	}

	protected abstract void generateBytes(ByteBuffer buf);

	public void reportCursorPos(int row, int col) {
		bb.put(("\033[" + row + ";" + col + "R").getBytes(charset));
		generateBytesExc();
	}

	protected void generateBytesExc() {
		bb.flip();
		try {
			generateBytes(bb);
		}
		catch (Throwable t) {
			Msg.error(this, "Error generating bytes: " + t, t);
		}
		finally {
			bb.clear();
		}
	}

	public void reportPasteStart() {
		bb.put(PASTE_START);
		generateBytesExc();
	}

	public void reportPasteEnd() {
		bb.put(PASTE_END);
		generateBytesExc();
	}

	public void reportDarkMode(boolean isDark) {
		bb.put(isDark ? THEME_DARK_MODE : THEME_LIGHT_MODE);
		generateBytesExc();
	}

	public void reportXTVersion(String name, String version) {
		byte[] bytes = "\033P>|%s(%s)\033\\".formatted(name, version).getBytes(charset);
		if (bytes.length > bb.capacity()) {
			int newCap = bb.capacity();
			while (bytes.length > newCap) {
				newCap *= 2;
			}
			bb = ByteBuffer.allocate(newCap);
		}
		bb.put(bytes);
		generateBytesExc();
	}
}
