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
import java.util.*;

import com.google.gson.JsonArray;

import generic.stl.Pair;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
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

	static String[] commentTags;
	static Map<String, CommentType> commentTypeMap;

	static {

		CommentType[] commentTypes = CommentType.values();
		commentTags = new String[commentTypes.length];
		commentTypeMap = new HashMap<>();

		for (CommentType type : commentTypes) {
			String tag;
			switch (type) {
				case PRE:
					tag = "pre";
					break;
				case POST:
					tag = "post";
					break;
				case EOL:
					tag = "end-of-line";
					break;
				case PLATE:
					tag = "plate";
					break;
				case REPEATABLE:
					tag = "repeatable";
					break;
				default:
					throw new RuntimeException("Missing comment type support: " + type.name());
			}
			commentTags[type.ordinal()] = tag;
			commentTypeMap.put(tag, type);
		}
	}

	CommentsSarifMgr(Program program, MessageLog log) {
		super(KEY, program, log);
	}

	////////////////////////////
	// SARIF READ CURRENT DTD //
	////////////////////////////

	@Override
	public boolean read(Map<String, Object> result, SarifProgramOptions options,
			TaskMonitor monitor) throws AddressFormatException, CancelledException {
		processComment(result);
		return true;
	}

	private void processComment(Map<String, Object> result) throws AddressFormatException {
		try {
			Address addr = getLocation(result);
			String typeStr = (String) result.get("kind");
			String comment = (String) result.get("value");
			boolean standard = (boolean) result.get("standard");
			CommentType commentType = getCommentType(typeStr);
			if (commentType == null) {
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
					}
					else if (currCmt.indexOf(comment) < 0) {
						log.appendMsg("Merged " + typeStr + " comment at " + addr);
						cu.setComment(commentType, currCmt + "\n" + comment);
					}
				}
			}
			else {
				String currCmt = listing.getComment(commentType, addr);
				if (currCmt == null || currCmt.length() == 0) {
					listing.setComment(addr, commentType, comment);
				}
				else if (currCmt.indexOf(comment) < 0) {
					log.appendMsg("Merged " + typeStr + " comment at " + addr);
					listing.setComment(addr, commentType, currCmt + "\n" + comment);
				}
			}
		}
		catch (Exception e) {
			log.appendException(e);
		}
	}

	public static CommentType getCommentType(String typeTagStr) {
		return commentTypeMap.get(typeTagStr);
	}

	public static String getCommentTypeString(CommentType type) {
		return commentTags[type.ordinal()];
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
	 * @throws CancelledException 
	 */
	void write(JsonArray results, AddressSetView set, TaskMonitor monitor)
			throws IOException, CancelledException {
		monitor.setMessage("Writing COMMENTS ...");

		if (set == null) {
			set = program.getMemory();
		}

		List<Pair<CodeUnit, Pair<String, String>>> request0 = new ArrayList<>();
		CodeUnitIterator iter = listing.getCodeUnitIterator(CodeUnit.COMMENT_PROPERTY, set, true);

		while (iter.hasNext()) {
			monitor.checkCancelled();
			CodeUnit cu = iter.next();
			for (CommentType type : CommentType.values()) {
				String[] comments = cu.getCommentAsArray(type);
				String typeStr = getCommentTypeString(type);
				for (String c : comments) {
					Pair<String, String> pair = new Pair<>(typeStr, c);
					request0.add(new Pair<CodeUnit, Pair<String, String>>(cu, pair));
				}
			}
		}

		writeAsSARIF0(request0, results);

		List<Pair<Address, Pair<String, String>>> request1 = new ArrayList<>();
		for (CommentType type : CommentType.values()) {
			AddressIterator aiter = listing.getCommentAddressIterator(type, set, true);
			while (aiter.hasNext()) {
				monitor.checkCancelled();
				Address a = aiter.next();
				CodeUnit cu = listing.getCodeUnitContaining(a);
				if (cu instanceof Instruction && !a.equals(cu.getMinAddress())) {
					String c = listing.getComment(type, a);
					Pair<String, String> pair = new Pair<>(getCommentTypeString(type), c);
					request1.add(new Pair<Address, Pair<String, String>>(a, pair));
				}
			}
		}

		writeAsSARIF1(request1, results);

	}

	public static void writeAsSARIF0(List<Pair<CodeUnit, Pair<String, String>>> request,
			JsonArray results) throws IOException {
		SarifCommentWriter writer = new SarifCommentWriter(request, null);
		new TaskLauncher(new SarifWriterTask(SUBKEY, writer, results), null);
	}

	public static void writeAsSARIF1(List<Pair<Address, Pair<String, String>>> request,
			JsonArray results) throws IOException {
		SarifCommentWriter writer = new SarifCommentWriter(null, request);
		new TaskLauncher(new SarifWriterTask(SUBKEY, writer, results), null);
	}

}
