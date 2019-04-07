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
package ghidra.plugins.importer.tasks;

import java.net.MalformedURLException;

import org.junit.Assert;
import org.junit.Test;

import ghidra.formats.gfilesystem.FSRL;

public class ImportBatchTaskTest {
	private static String mkFSRL(int depth) {
		String result = "fsrl://";
		for (int i = 0; i < depth; i++) {
			result += "/";
			result += (char) ('a' + i);
		}
		return result;
	}

	private static void iterateFsrlToPathParamPermutations(int srcDepth, int targetDepth)
			throws MalformedURLException {
		FSRL src = FSRL.fromString(mkFSRL(srcDepth));
		FSRL target = FSRL.fromString(mkFSRL(targetDepth));
		System.out.println("--------------------------------------------------------------");
		System.out.println("Testing: target depth " + targetDepth + ", src depth: " + srcDepth);
		System.out.println(String.format("%20s  %20s [%s] = %20s", src, target, "FF",
			ImportBatchTask.fsrlToPath(target, src, false, false)));
		System.out.println(String.format("%20s  %20s [%s] = %20s", src, target, "TF",
			ImportBatchTask.fsrlToPath(target, src, true, false)));
		System.out.println(String.format("%20s  %20s [%s] = %20s", src, target, "FT",
			ImportBatchTask.fsrlToPath(target, src, false, true)));
		System.out.println(String.format("%20s  %20s [%s] = %20s", src, target, "TT",
			ImportBatchTask.fsrlToPath(target, src, true, true)));
		System.out.println("--------------------------------------------------------------");
	}

	/*
	 * Disabled utility test to dump out all variations of paths created by the FSRLToPath()
	 * method.
	 */
	//@Test
	public void iterateAllOutputOptions() throws MalformedURLException {
		for (int i = 1; i < 5; i++) {
			for (int j = i; j > 0; j--) {
				iterateFsrlToPathParamPermutations(j, i);
			}
		}
	}

	@Test
	public void testNoNested() throws MalformedURLException {
		FSRL fsrl = FSRL.fromString("fsrl:///a/b");
		Assert.assertEquals("/a/b", ImportBatchTask.fsrlToPath(fsrl, fsrl, false, false));
	}

	@Test
	public void testNoNested_StripLeading() throws MalformedURLException {
		FSRL fsrl = FSRL.fromString("fsrl:///a/b");
		Assert.assertEquals("b", ImportBatchTask.fsrlToPath(fsrl, fsrl, true, false));
	}

	@Test
	public void testNestedSingleLvl() throws MalformedURLException {
		FSRL src = FSRL.fromString("fsrl:///a");
		FSRL fsrl = FSRL.fromString("fsrl:///a/b");
		Assert.assertEquals("/a/b", ImportBatchTask.fsrlToPath(fsrl, src, false, false));
		Assert.assertEquals("a/b", ImportBatchTask.fsrlToPath(fsrl, src, true, false));
	}

	@Test
	public void testNestedDeeper() throws MalformedURLException {
		FSRL src_bfile = FSRL.fromString("fsrl:///a/b");
		FSRL target_efile = FSRL.fromString("fsrl:///a/b/c/d/e");
		Assert.assertEquals("/a/b/c/d/e",
			ImportBatchTask.fsrlToPath(target_efile, src_bfile, false, false));
		Assert.assertEquals("b/c/d/e",
			ImportBatchTask.fsrlToPath(target_efile, src_bfile, true, false));
		Assert.assertEquals("/a/b/e",
			ImportBatchTask.fsrlToPath(target_efile, src_bfile, false, true));
		Assert.assertEquals("b/e", ImportBatchTask.fsrlToPath(target_efile, src_bfile, true, true));
	}

}
