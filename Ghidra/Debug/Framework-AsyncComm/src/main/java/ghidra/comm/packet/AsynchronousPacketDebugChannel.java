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

import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousByteChannel;
import java.util.concurrent.CompletableFuture;

import ghidra.util.Msg;

/**
 * An extension to {@link AsynchronousPacketChannel} that prints packets to the debug log
 * 
 * @param <S> the type of packet sent, possibly an abstract type
 * @param <R> the type of packet received, possibly an abstract type
 */
public class AsynchronousPacketDebugChannel<S extends Packet, R extends Packet>
		extends AsynchronousPacketChannel<S, R> {

	public AsynchronousPacketDebugChannel(AsynchronousByteChannel channel,
			AbstractPacketMarshaller<S, R, ByteBuffer> marshaller) {
		super(channel, marshaller);
	}

	@Override
	public <R2 extends R> CompletableFuture<R2> read(Class<R2> pktType) {
		return super.read(pktType).thenApply((pkt) -> {
			Msg.debug(this, "PACKET Read: " + pkt);
			return pkt;
		});
	}

	@Override
	public CompletableFuture<Integer> write(S pkt) {
		Msg.debug(this, "PACKET Write: " + pkt);
		return super.write(pkt).thenApply((len) -> {
			return len;
		});
	}
}
