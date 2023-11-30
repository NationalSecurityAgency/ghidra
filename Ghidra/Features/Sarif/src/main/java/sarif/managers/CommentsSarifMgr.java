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
package sarif.managers;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.google.gson.JsonArray;

import generic.stl.Pair;
import ghidra.app.util.CommentTypes;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import sarif.SarifProgramOptions;
import sarif.export.SarifWriterTask;
import sarif.export.comments.SarifCommentWriter;

/**
 * SARIF manager for all types of comments.
 */
public class CommentsSarifMgr extends SarifMgr {

	public static String KEY = "COMMENTS";
	public static String SUBKEY = "Comment";

	public static int[] COMMENT_TYPES;
	public static String[] COMMENT_TAGS;

	public static String[] COMMENT_TAGS2 = { "end-of-line", "pre", "post", "plate", "repeatable" };

	static {
		COMMENT_TYPES = CommentTypes.getTypes();

		COMMENT_TAGS = new String[COMMENT_TYPES.length];
		for (int i = 0; i < COMMENT_TAGS.length; i++) {

			switch (COMMENT_TYPES[i]) {
			case CodeUnit.PRE_COMMENT:
				COMMENT_TAGS[i] = "pre";
				break;
			case CodeUnit.POST_COMMENT:
				COMMENT_TAGS[i] = "post";
				break;
			case CodeUnit.EOL_COMMENT:
				COMMENT_TAGS[i] = "end-of-line";
				break;
			case CodeUnit.PLATE_COMMENT:
				COMMENT_TAGS[i] = "plate";
				break;
			case CodeUnit.REPEATABLE_COMMENT:
				COMMENT_TAGS[i] = "repeatable";
				break;
			}
		}
	}

	CommentsSarifMgr(Program program, MessageLog log) {
		super(KEY, program, log);
	}

	////////////////////////////
	// SARIF READ CURRENT DTD //
	////////////////////////////

	/**
	 * Process the entry point section of the SARIF file.
	 * 
	 * @param result  sarif reader
	 * @param monitor monitor that can be canceled
	 */
	@Override
	public boolean read(Map<String, Object> result, SarifProgramOptions options, TaskMonitor monitor)
			throws AddressFormatException, CancelledException {
		processComment(result, result);
		return true;
	}

	private void processComment(Map<String, Object> result, Map<String, Object> result2) throws AddressFormatException {
		try {
			Address addr = getLocation(result);
			String typeStr = (String) result.get("kind");
			String comment = (String) result.get("value");
			boolean standard = (boolean) result.get("standard");
			int commentType = getCommentType(typeStr);
			if (commentType < 0) {
				log.appendMsg("Unknown comment type: " + typeStr);
				return;
			}
			if (standard) {
				CodeUnit cu = listing.getCodeUnitContaining(addr);
				if (cu != null) {
					// if a comment already exists, then merge...
					//
					String currCmt = cu.getComment(commentType);
					if (currCmt == null || currCmt.length() == 0) {
						cu.setComment(commentType, comment);
					} else if (currCmt.indexOf(comment) < 0) {
						log.appendMsg("Merged " + typeStr + " comment at " + addr);
						cu.setComment(commentType, currCmt + "\n" + comment);
					}
				}
			} else {
				String currCmt = listing.getComment(commentType, addr);
				if (currCmt == null || currCmt.length() == 0) {
					listing.setComment(addr, commentType, comment);
				} else if (currCmt.indexOf(comment) < 0) {
					log.appendMsg("Merged " + typeStr + " comment at " + addr);
					listing.setComment(addr, commentType, currCmt + "\n" + comment);
				}
			}
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	private int getCommentType(String typeStr) {
		for (int i = 0; i < COMMENT_TAGS.length; i++) {
			if (COMMENT_TAGS[i].equals(typeStr)) {
				return COMMENT_TYPES[i];
			}
		}
		return -1; // unknown comment
	}

	/////////////////////////////
	// SARIF WRITE CURRENT DTD //
	/////////////////////////////

	/**
	 * Write out the SARIF for the external entry points.
	 * 
	 * @param results writer for SARIF
	 * @param set     address set that is either the entire program or a selection
	 * @param monitor monitor that can be canceled should be written
	 * @throws IOException
	 */
	void write(JsonArray results, AddressSetView set, TaskMonitor monitor) throws IOException, CancelledException {
		monitor.setMessage("Writing COMMENTS ...");

		if (set == null) {
			set = program.getMemory();
		}

		List<Pair<CodeUnit, Pair<String, String>>> request0 = new ArrayList<>();
		CodeUnitIterator iter = listing.getCodeUnitIterator(CodeUnit.COMMENT_PROPERTY, set, true);

		while (iter.hasNext()) {
			monitor.checkCancelled();
			CodeUnit cu = iter.next();
			for (int i = 0; i < COMMENT_TYPES.length; i++) {
				String[] comments = cu.getCommentAsArray(COMMENT_TYPES[i]);
				for (String c : comments) {
					Pair<String, String> pair = new Pair<>(COMMENT_TAGS[i], c);
					request0.add(new Pair<CodeUnit, Pair<String, String>>(cu, pair));
				}
			}
		}

		writeAsSARIF0(request0, results);

		List<Pair<Address, Pair<String, String>>> request1 = new ArrayList<>();
		for (int i = 0; i < COMMENT_TAGS2.length; i++) {
			AddressIterator aiter = listing.getCommentAddressIterator(i, set, true);
			while (aiter.hasNext()) {
				monitor.checkCancelled();
				Address a = aiter.next();
				CodeUnit cu = listing.getCodeUnitContaining(a);
				if (cu instanceof Instruction && !a.equals(cu.getMinAddress())) {
					String c = listing.getComment(i, a);
					Pair<String, String> pair = new Pair<>(COMMENT_TAGS2[i], c);
					request1.add(new Pair<Address, Pair<String, String>>(a, pair));
				}
			}
		}

		writeAsSARIF1(request1, results);

	}

	public static void writeAsSARIF0(List<Pair<CodeUnit, Pair<String, String>>> request, JsonArray results)
			throws IOException {
		SarifCommentWriter writer = new SarifCommentWriter(request, null);
		new TaskLauncher(new SarifWriterTask(SUBKEY, writer, results), null);
	}

	public static void writeAsSARIF1(List<Pair<Address, Pair<String, String>>> request, JsonArray results)
			throws IOException {
		SarifCommentWriter writer = new SarifCommentWriter(null, request);
		new TaskLauncher(new SarifWriterTask(SUBKEY, writer, results), null);
	}

}
