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
package sarif.export.comments;

import java.io.IOException;
import java.io.Writer;
import java.util.List;

import generic.stl.Pair;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import sarif.export.AbstractExtWriter;
import sarif.export.SarifObject;
import sarif.managers.CommentsSarifMgr;

public class SarifCommentWriter extends AbstractExtWriter {

	private List<Pair<CodeUnit, Pair<String, String>>> comments0;
	private List<Pair<Address, Pair<String, String>>> comments1;

	public SarifCommentWriter(List<Pair<CodeUnit, Pair<String, String>>> target, Writer baseWriter) throws IOException {
		super(baseWriter);
		this.comments0 = target;
	}

	public SarifCommentWriter(Writer baseWriter, List<Pair<Address, Pair<String, String>>> target) throws IOException {
		super(baseWriter);
		this.comments1 = target;
	}

	@Override
	protected void genRoot(TaskMonitor monitor) throws CancelledException, IOException {
		genComments0(monitor);
		genComments1(monitor);
		root.add("comments", objects);
	}

	private void genComments0(TaskMonitor monitor) throws CancelledException, IOException {
		if (comments0 == null) {
			return;
		}
		monitor.initialize(comments0.size());
		for (Pair<CodeUnit, Pair<String, String>> pair : comments0) {
			CodeUnit cu = pair.first;
			ExtComment isf = new ExtComment(pair.second, true);
			SarifObject sarif = new SarifObject(CommentsSarifMgr.SUBKEY, CommentsSarifMgr.KEY, getTree(isf), cu.getMinAddress(),
					cu.getMaxAddress());
			objects.add(getTree(sarif));
			monitor.increment();
		}
	}

	private void genComments1(TaskMonitor monitor) throws CancelledException, IOException {
		if (comments1 == null) {
			return;
		}
		monitor.initialize(comments1.size());
		for (Pair<Address, Pair<String, String>> pair : comments1) {
			Address addr = pair.first;
			ExtComment isf = new ExtComment(pair.second, false);
			SarifObject sarif = new SarifObject(CommentsSarifMgr.SUBKEY, CommentsSarifMgr.KEY, getTree(isf), addr, addr);
			objects.add(getTree(sarif));
			monitor.increment();
		}
	}

}
