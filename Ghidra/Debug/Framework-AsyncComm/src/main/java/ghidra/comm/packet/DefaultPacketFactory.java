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

/**
 * The default {@link PacketFactory}
 * 
 * This factory is used for unversioned protocols, or for versioned protocols before the version has
 * been negotiated. It is up to the developer to negotiate the version, since each protocol
 * accomplishes this differently. The packets exchanged before and during negotiation ought not to
 * depend on any particular {@link PacketFactory}. If so, the protocol itself suffers from a serious
 * flaw.
 * 
 * {@link PacketCodec#decodePacket(Class, Object)} uses this factory. It is a singleton instance.
 * 
 * This factory does not register any additional, nor does it perform any substitutions aside from
 * those applied by {@link AbstractPacketFactory}.
 */
public final class DefaultPacketFactory extends AbstractPacketFactory {
	public static final DefaultPacketFactory INSTANCE = new DefaultPacketFactory();

	private DefaultPacketFactory() {
	}

	public static DefaultPacketFactory getInstance() {
		return INSTANCE;
	}
}
