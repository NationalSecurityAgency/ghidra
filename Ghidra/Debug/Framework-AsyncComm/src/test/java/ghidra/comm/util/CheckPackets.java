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
package ghidra.comm.util;

import java.io.IOException;
import java.net.*;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;

import org.junit.Ignore;
import org.junit.Test;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.PacketCodec;
import ghidra.comm.packet.string.StringPacketCodec;
import ghidra.util.Msg;

@Ignore("Not high priority")
public class CheckPackets {
	@Test
	public void testRegisterAll() throws IOException, URISyntaxException {
		registerAll(StringPacketCodec.getInstance());
	}

	public static void registerAll(PacketCodec<?> codec) throws IOException, URISyntaxException {
		URLClassLoader loader = (URLClassLoader) CheckPackets.class.getClassLoader();
		for (URL url : loader.getURLs()) {
			Path root = Paths.get(url.toURI());
			Files.walkFileTree(root, new SimpleFileVisitor<Path>() {
				@SuppressWarnings("unchecked")
				@Override
				public FileVisitResult visitFile(Path file, BasicFileAttributes attrs)
						throws IOException {
					if (!file.endsWith(".class")) {
						return FileVisitResult.CONTINUE;
					}
					String relPath = root.relativize(file).toString();
					String clsName = relPath.substring(0, relPath.length() - ".class".length())
							.replace('/', '.');
					Class<?> cls;
					try {
						cls = loader.loadClass(clsName);
					}
					catch (ClassNotFoundException e) {
						throw new RuntimeException(e);
					}
					if (Packet.class.isAssignableFrom(cls)) {
						try {
							codec.registerPacketType((Class<? extends Packet>) cls);
						}
						catch (Exception e) {
							Msg.error(CheckPackets.class,
								"Problem registering packet: " + e.getMessage());
						}
					}
					return FileVisitResult.CONTINUE;
				}
			});
		}
	}
}
