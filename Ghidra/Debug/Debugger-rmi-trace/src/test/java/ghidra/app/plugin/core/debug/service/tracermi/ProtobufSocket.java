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
package ghidra.app.plugin.core.debug.service.tracermi;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

import com.google.protobuf.AbstractMessage;
import com.google.protobuf.InvalidProtocolBufferException;

public class ProtobufSocket<T extends AbstractMessage> {
	public interface Decoder<T> {
		T decode(ByteBuffer buf) throws InvalidProtocolBufferException;
	}

	private final ByteBuffer lenSend = ByteBuffer.allocate(4);
	private final ByteBuffer lenRecv = ByteBuffer.allocate(4);
	private final SocketChannel channel;
	private final Decoder<T> decoder;

	public ProtobufSocket(SocketChannel channel, Decoder<T> decoder) {
		this.channel = channel;
		this.decoder = decoder;
	}

	public void send(T msg) throws IOException {
		synchronized (lenSend) {
			lenSend.clear();
			lenSend.putInt(msg.getSerializedSize());
			lenSend.flip();
			channel.write(lenSend);
			for (ByteBuffer buf : msg.toByteString().asReadOnlyByteBufferList()) {
				channel.write(buf);
			}
		}
	}

	public T recv() throws IOException {
		synchronized (lenRecv) {
			lenRecv.clear();
			while (lenRecv.hasRemaining()) {
				channel.read(lenRecv);
			}
			lenRecv.flip();
			int len = lenRecv.getInt();
			// This is just for testing, so littering on the heap is okay.
			ByteBuffer buf = ByteBuffer.allocate(len);
			while (buf.hasRemaining()) {
				channel.read(buf);
			}
			buf.flip();
			return decoder.decode(buf);
		}
	}
}
