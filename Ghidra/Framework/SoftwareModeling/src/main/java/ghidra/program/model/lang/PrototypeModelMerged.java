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
package ghidra.program.model.lang;

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import java.io.IOException;
import java.util.*;

import ghidra.app.plugin.processors.sleigh.SleighException;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.Encoder;
import ghidra.xml.*;

/**
 * This model serves as a placeholder for multiple model
 * Currently all the models being selected between must share the same output model
 *
 */
public class PrototypeModelMerged extends PrototypeModel {

	private PrototypeModel[] modellist;			// models we are trying to distinguish between

	public PrototypeModelMerged() {
		super();
		modellist = null;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.lang.PrototypeModel#isMerged()
	 */
	@Override
	public boolean isMerged() {
		return true;
	}

	public int numModels() {
		return modellist.length;
	}

	public PrototypeModel getModel(int i) {
		return modellist[i];
	}

	@Override
	public void encode(Encoder encoder, PcodeInjectLibrary injectLibrary) throws IOException {
		encoder.openElement(ELEM_RESOLVEPROTOTYPE);
		encoder.writeString(ATTRIB_NAME, name);
		for (PrototypeModel model : modellist) {
			encoder.openElement(ELEM_MODEL);
			encoder.writeString(ATTRIB_NAME, model.name);
			encoder.closeElement(ELEM_MODEL);
		}
		encoder.closeElement(ELEM_RESOLVEPROTOTYPE);
	}

	public void restoreXml(XmlPullParser parser, List<PrototypeModel> modelList)
			throws XmlParseException {
		ArrayList<PrototypeModel> mylist = new ArrayList<>();
		XmlElement el = parser.start();
		name = el.getAttribute("name");
		while (parser.peek().isStart()) {
			XmlElement subel = parser.start();
			String modelName = subel.getAttribute("name");
			PrototypeModel foundModel = null;
			for (PrototypeModel model : modelList) {
				if (model.name.equals(modelName)) {
					foundModel = model;
					break;
				}
			}
			if (foundModel == null) {
				throw new XmlParseException("Missing prototype model: " + modelName);
			}
			mylist.add(foundModel);
			parser.end(subel);
		}
		parser.end(el);
		modellist = new PrototypeModel[mylist.size()];
		mylist.toArray(modellist);
	}

	public PrototypeModel selectModel(Parameter[] params) throws SleighException {
		int bestscore = 500;
		int bestindex = -1;
		for (int i = 0; i < modellist.length; ++i) {
			ScoreProtoModel scoremodel = new ScoreProtoModel(true, modellist[i], params.length);
			for (Parameter p : params) {
				VariableStorage storage = p.getVariableStorage();
				if (storage.isUnassignedStorage() || storage.isBadStorage()) {
					continue;
				}
				scoremodel.addParameter(storage.getMinAddress(), p.getLength());
			}
			scoremodel.doScore();
			int score = scoremodel.getScore();
			if (score < bestscore) {
				bestscore = score;
				bestindex = i;
				if (bestscore == 0) {
					break;				// Can't get any lower
				}
			}
		}
		if (bestindex >= 0) {
			return modellist[bestindex];
		}
		throw new SleighException("No model matches : missing default");
	}

	private static class PEntry implements Comparable<PEntry> {
//		public int origIndex;			// Original index of parameter
		public int slot;				// slot within the list
		public int size;				// number of slots occupied

		@Override
		public int compareTo(PEntry o) {
			if (slot != o.slot) {
				return (slot < o.slot) ? -1 : 1;
			}
			return 0;
		}
	}

	private static class ScoreProtoModel {
		private boolean isinputscore;		// true for prototype inputs, false for prototype outputs
		private ArrayList<PEntry> entry;
		private PrototypeModel model;
		private int finalscore;
		private int mismatch;

		public ScoreProtoModel(boolean isinput, PrototypeModel mod, int numparam) {
			isinputscore = isinput;
			model = mod;
			entry = new ArrayList<>(numparam);
			finalscore = -1;
			mismatch = 0;
		}

		public int getScore() {
			return finalscore;
		}

		public void addParameter(Address addr, int sz) {
//			int orig = entry.size();
			ParamList.WithSlotRec rec = new ParamList.WithSlotRec();
			boolean isparam;

			if (isinputscore) {
				isparam = model.possibleInputParamWithSlot(addr, sz, rec);
			}
			else {
				isparam = model.possibleOutputParamWithSlot(addr, sz, rec);
			}

			if (isparam) {
				PEntry pe = new PEntry();
//				pe.origIndex = orig;
				pe.slot = rec.slot;
				pe.size = rec.slotsize;
				entry.add(pe);
			}
			else {
				mismatch += 1;
			}
		}

		public void doScore() {
			Collections.sort(entry); 		// Sort our entries via slot

			int nextfree = 0;				// Next slot we expect to see
			int basescore = 0;
			int[] penalty = new int[4];
			penalty[0] = 16;
			penalty[1] = 10;
			penalty[2] = 7;
			penalty[3] = 5;
			int penaltyfinal = 3;
			int mismatchpenalty = 20;

			for (PEntry p : entry) {
				if (p.slot > nextfree) {		// We have some kind of hole in our slot coverage
					while (nextfree < p.slot) {
						if (nextfree < 4) {
							basescore += penalty[nextfree];
						}
						else {
							basescore += penaltyfinal;
						}
						nextfree += 1;
					}
					nextfree += p.size;
				}
				else if (nextfree > p.slot) {		// Some kind of slot duplication
					basescore += mismatchpenalty;
					if (p.slot + p.size > nextfree) {
						nextfree = p.slot + p.size;
					}
				}
				else {
					nextfree = p.slot + p.size;
				}
			}
			finalscore = basescore + mismatchpenalty * mismatch;
		}
	}

	@Override
	public boolean isEquivalent(PrototypeModel obj) {
		if (getClass() != obj.getClass()) {
			return false;
		}
		PrototypeModelMerged op2 = (PrototypeModelMerged) obj;
		if (modellist.length != op2.modellist.length) {
			return false;
		}
		for (int i = 0; i < modellist.length; ++i) {
			if (!modellist[i].getName().equals(op2.modellist[i].getName())) {
				return false;
			}
		}
		return true;
	}
}
