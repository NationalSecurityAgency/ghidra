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
package mdemangler;

import java.util.*;

import ghidra.util.Msg;

/**
 * An MDMang extension that outputs debugging parse information.
 */
public class MDMangParseInfo extends MDMang {

	private class MDParseInfo {
		private int startIndex;
		private int itemDepth;
		private String itemName;

		public MDParseInfo(int startIndex, int itemDepth, String itemName) {
			this.startIndex = startIndex;
			this.itemDepth = itemDepth;
			this.itemName = itemName;
		}

		public String getItemName() {
			return itemName;
		}

		public int getStartIndex() {
			return startIndex;
		}
	}

	private Stack<MDParseInfo> infoStack = new Stack<>();
	private List<MDParseInfo> infoList = new ArrayList<>();
	private int parseInfoMangledIndex = 0;
	private StringBuilder parseInfoBuilder = new StringBuilder();

	@Override // Override might be temporary, depending on how we answer questions in MDMang
	public void parseInfoPushPop(int startIndexOffset, String itemName) {
		parseInfoPush(startIndexOffset, itemName);
		parseInfoPop();
	}

	@Override // Override might be temporary, depending on how we answer questions in MDMang
	public void parseInfoPush(int startIndexOffset, String itemName) {
		MDParseInfo info =
			new MDParseInfo(iter.getIndex() - startIndexOffset, infoStack.size(), itemName);
		infoStack.push(info);
		infoList.add(info);
		parseInfoMangledIndex =
			doParseInfoSingle(parseInfoBuilder, parseInfoMangledIndex, infoList.size() - 1);
	}

	@Override // Override might be temporary, depending on how we answer questions in MDMang
	public void parseInfoPop() {
		int index =
			Integer.max(iter.getIndex() - 1, infoList.get(infoList.size() - 1).getStartIndex());
		MDParseInfo oldInfo = infoStack.pop();
		MDParseInfo info =
			new MDParseInfo(index, infoStack.size(), oldInfo.getItemName() + " -- END");
		infoList.add(info);
		parseInfoMangledIndex =
			doParseInfoSingle(parseInfoBuilder, parseInfoMangledIndex, infoList.size() - 1);
	}

	public String getParseInfoIncremental() {
		return parseInfoBuilder.toString();
	}

	private static final String TAB0 = "       ";
	private static final String TAB1A = "|  ";
	private static final String TAB1B = "|";
	private static final String TAB2 = "+--";
	private static final String EOL = "\n";

	private void outputMangledCharAndInfo(StringBuilder builder, int index, int depth,
			String itemName) {
		if (index >= 0) {
			if (index < mangled.length()) {
				builder.append(String.format("%04d %c ", index, mangled.charAt(index)));
			}
			else {
				builder.append(String.format("%04d   ", index));
			}
		}
		else {
			builder.append(TAB0);
		}
		if (itemName == null) {
			// Output line that looks like: "C |  |  |  |"
			while (depth-- > 0) {
				builder.append(TAB1A);
			}
			builder.append(TAB1B);
		}
		else {
			// Output line that looks like: "C +--+--+--Item"
			while (depth-- > 0) {
				builder.append(TAB2);
			}
			builder.append(itemName);
		}
		builder.append(EOL);
	}

	public String getParseInfo_orig() {
		StringBuilder builder = new StringBuilder();
		int mangledIndex = 0;
		int infoIndex = 0;
		while (infoIndex < infoList.size()) {
			// Output one line that looks like: "C +--+--+--Item"
			if (mangledIndex == infoList.get(infoIndex).startIndex) {
				outputMangledCharAndInfo(builder, mangledIndex, infoList.get(infoIndex).itemDepth,
					infoList.get(infoIndex).itemName);
				// Output multiple lines that looks like: "  +--+--+--Item"
				while ((++infoIndex < infoList.size()) &&
					(mangledIndex == infoList.get(infoIndex).startIndex)) {
					outputMangledCharAndInfo(builder, -1, infoList.get(infoIndex).itemDepth,
						infoList.get(infoIndex).itemName);
				}
			}
			// Doing ">= mangled.length(), allowing for one additional character for optional
			//  parsable items after the last mangled character
			else if ((mangledIndex >= mangled.length()) ||
				(mangledIndex == infoList.get(infoIndex).startIndex)) {
				// Problem
				Msg.warn(this, "Problem with Parse Info Stack");
				break;
			}
			else {
				// Output multiple lines that looks like: "C |  |  |  |"
				while ((mangledIndex < infoList.get(infoIndex).startIndex)) {
					if ((infoIndex == 0) || ((infoIndex != 0) &&
						(mangledIndex > infoList.get(infoIndex - 1).startIndex))) {
						outputMangledCharAndInfo(builder, mangledIndex,
							infoList.get(infoIndex).itemDepth, null);
					}
					mangledIndex++;
				}
			}
		}
		return builder.toString();
	}

	public String getParseInfo() {
		StringBuilder builder = new StringBuilder();
		int parseInfoMangledIndexLocal = 0;
		int infoIndex = 0;
		while (infoIndex < infoList.size()) {
			parseInfoMangledIndexLocal =
				doParseInfoSingle(builder, parseInfoMangledIndexLocal, infoIndex++);
		}
		return builder.toString();
	}

	public int doParseInfoSingle(StringBuilder builder, int parseInfoMangledIndexArg,
			int infoIndex) {
		// Output multiple lines that looks like: "C |  |  |  |"
		//  This is because we are not recording each individual getAndIncrement()--we would
		//  probably 		//  need to make some additional changes to the processing routines
		//  for when peek(n) and getAndIncrement() are used... some sort of contractual
		//  agreement on when the character read is actually put into the parseInfo.
		while ((parseInfoMangledIndexArg < infoList.get(infoIndex).startIndex)) {
			if ((infoIndex == 0) || ((infoIndex != 0) &&
				(parseInfoMangledIndexArg > infoList.get(infoIndex - 1).startIndex))) {
				outputMangledCharAndInfo(builder, parseInfoMangledIndexArg,
					infoList.get(infoIndex).itemDepth, null);
			}
			parseInfoMangledIndexArg++;
		}
		if (parseInfoMangledIndexArg >= infoList.get(infoIndex).startIndex) {
			if ((infoIndex == 0) ||
				(infoList.get(infoIndex).startIndex != infoList.get(infoIndex - 1).startIndex)) {
				// Output one line that looks like: "C +--+--+--Item"
				outputMangledCharAndInfo(builder, infoList.get(infoIndex).startIndex,
					infoList.get(infoIndex).itemDepth, infoList.get(infoIndex).itemName);
			}
			else {
				// Output multiple lines that looks like: "  +--+--+--Item"
				outputMangledCharAndInfo(builder, -1, infoList.get(infoIndex).itemDepth,
					infoList.get(infoIndex).itemName);
			}
		}
		return parseInfoMangledIndexArg;
	}
}

/******************************************************************************/
/******************************************************************************/
