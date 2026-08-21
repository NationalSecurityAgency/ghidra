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
package ghidra.program.database.sourcemap;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;

import ghidra.framework.store.LockException;
import ghidra.program.model.sourcemap.SourceMapEntry;

public class GetSourceFilesTest extends AbstractSourceFileTest {

	@Test
	public void testGetAllSourceFiles() throws LockException {
		List<SourceFile> sourceFiles = sourceManager.getAllSourceFiles();
		assertEquals(3, sourceFiles.size());
		assertTrue(sourceFiles.contains(source1));
		assertTrue(sourceFiles.contains(source2));
		assertTrue(sourceFiles.contains(source3));

		int txId = program.startTransaction("deleting source file 2");
		try {
			sourceManager.removeSourceFile(source2);
		}
		finally {
			program.endTransaction(txId, true);
		}

		sourceFiles = sourceManager.getAllSourceFiles();
		assertEquals(2, sourceFiles.size());
		assertTrue(sourceFiles.contains(source1));
		assertTrue(sourceFiles.contains(source3));

		txId = program.startTransaction("deleting source files");
		try {
			sourceManager.removeSourceFile(source1);
			sourceManager.removeSourceFile(source3);
		}
		finally {
			program.endTransaction(txId, true);
		}

		assertTrue(sourceManager.getAllSourceFiles().isEmpty());
	}

	@Test
	public void testGetMappedSourceFiles() throws LockException {
		List<SourceFile> sourceFiles = sourceManager.getMappedSourceFiles();
		assertTrue(sourceFiles.isEmpty());

		int txId = program.startTransaction("adding source map info");
		try {
			sourceManager.addSourceMapEntry(source1, 1, getBody(ret2_1));
		}
		finally {
			program.endTransaction(txId, true);
		}

		sourceFiles = sourceManager.getMappedSourceFiles();
		assertEquals(1, sourceFiles.size());
		SourceFile file = sourceFiles.get(0);
		assertEquals(source1.getPath(), file.getPath());

		txId = program.startTransaction("adding source map info");
		try {
			sourceManager.addSourceMapEntry(source2, 1, getBody(ret2_2));
		}
		finally {
			program.endTransaction(txId, true);
		}

		sourceFiles = sourceManager.getMappedSourceFiles();
		assertEquals(2, sourceFiles.size());
		assertTrue(sourceFiles.contains(source1));
		assertTrue(sourceFiles.contains(source2));

		txId = program.startTransaction("transferring source map entries");
		try {
			sourceManager.transferSourceMapEntries(source2, source3);
		}
		finally {
			program.endTransaction(txId, true);
		}

		sourceFiles = sourceManager.getMappedSourceFiles();
		assertEquals(2, sourceFiles.size());
		assertTrue(sourceFiles.contains(source1));
		assertTrue(sourceFiles.contains(source3));

		txId = program.startTransaction("deleting source1");
		try {
			sourceManager.removeSourceFile(source1);
		}
		finally {
			program.endTransaction(txId, true);
		}

		sourceFiles = sourceManager.getMappedSourceFiles();
		assertEquals(1, sourceFiles.size());
		assertTrue(sourceFiles.contains(source3));

		txId = program.startTransaction("clearing mapping info for source3");
		try {
			List<SourceMapEntry> entries = sourceManager.getSourceMapEntries(source3);
			for (SourceMapEntry entry : entries) {
				assertTrue(sourceManager.removeSourceMapEntry(entry));
			}
		}
		finally {
			program.endTransaction(txId, true);
		}
		sourceFiles = sourceManager.getMappedSourceFiles();
		assertTrue(sourceFiles.isEmpty());
	}
}
