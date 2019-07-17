/* ###
 * IP: Public Domain
 */
package mobiledevices.dmg.reader;

import java.io.IOException;
import java.io.InputStream;

import org.catacombae.io.ReadableRandomAccessStream;

/**
 * A class to wrap a ReadableRandomAccessStream
 * so it may be used as a conventional
 * input stream.
 */
public class DmgInputStream extends InputStream {
	private ReadableRandomAccessStream stream;

	DmgInputStream(ReadableRandomAccessStream stream) {
		this.stream = stream;
	}

	public long getLength() {
		return stream.length();
	}

	@Override
	public int read() throws IOException {
		return stream.read();
	}

	@Override
	public int read(byte [] b) throws IOException {
		return stream.read(b);
	}

	@Override
	public int read(byte [] b, int off, int len) throws IOException {
		return stream.read(b, off, len);
	}

	
}
