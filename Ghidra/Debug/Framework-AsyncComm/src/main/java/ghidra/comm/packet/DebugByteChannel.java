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
package ghidra.comm.packet;

import static ghidra.async.AsyncUtils.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousByteChannel;
import java.nio.channels.CompletionHandler;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;

import ghidra.async.TypeSpec;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;

/**
 * A wrapper for an {@link AsynchronousByteChannel} that logs the transferred data.
 */
public class DebugByteChannel implements AsynchronousByteChannel {
	private final AsynchronousByteChannel wrapped;

	/**
	 * Wrap the given channel
	 * 
	 * @param wrapped the channel to wrap
	 */
	public DebugByteChannel(AsynchronousByteChannel wrapped) {
		this.wrapped = wrapped;
	}

	@Override
	public void close() throws IOException {
		wrapped.close();
	}

	@Override
	public boolean isOpen() {
		return wrapped.isOpen();
	}

	@Override
	public <A> void read(ByteBuffer dst, A attachment,
			CompletionHandler<Integer, ? super A> handler) {
		int start = dst.position();
		CompletableFuture<Integer> future = sequence(TypeSpec.INT).then((seq) -> {
			completable(TypeSpec.INT, wrapped::read, dst).handle(seq::next);
		}, TypeSpec.INT).then((len, seq) -> {
			if (len == -1) {
				Msg.debug(this, "Read EOF");
			}
			else {
				byte[] data = new byte[len];
				dst.position(start);
				dst.get(data);
				Msg.debug(this, "Read: " + NumericUtilities.convertBytesToString(data));
			}
			seq.exit(len, null);
		}).finish();
		handle(future, attachment, handler);
	}

	@Override
	public Future<Integer> read(ByteBuffer dst) {
		throw new UnsupportedOperationException();
	}

	@Override
	public <A> void write(ByteBuffer src, A attachment,
			CompletionHandler<Integer, ? super A> handler) {
		int start = src.position();
		CompletableFuture<Integer> future = sequence(TypeSpec.INT).then((seq) -> {
			completable(TypeSpec.INT, wrapped::write, src).handle(seq::next);
		}, TypeSpec.INT).then((len, seq) -> {
			byte[] data = new byte[len];
			src.position(start);
			src.get(data);
			Msg.debug(this, "Wrote: " + NumericUtilities.convertBytesToString(data));
			seq.exit(len, null);
		}).finish();
		handle(future, attachment, handler);
	}

	@Override
	public Future<Integer> write(ByteBuffer src) {
		throw new UnsupportedOperationException();
	}
}
