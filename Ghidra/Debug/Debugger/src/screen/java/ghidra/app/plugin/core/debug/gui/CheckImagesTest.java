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
package ghidra.app.plugin.core.debug.gui;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.Test;

public class CheckImagesTest {
	@Test
	public void testCheckForEmptyImages() throws IOException {
		Path path = Paths.get("src/main/help");
		Set<Path> missing = Files.walk(path).filter(p -> {
			File f = p.toFile();
			if (!f.isFile()) {
				return false;
			}
			if (!f.getName().endsWith(".png")) {
				return false;
			}
			if (f.length() != 0) {
				return false;
			}
			return true;
		}).collect(Collectors.toSet());
		assertEquals(Set.of(), missing);
	}
}
