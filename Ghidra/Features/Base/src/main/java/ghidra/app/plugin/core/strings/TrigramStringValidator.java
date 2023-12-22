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
package ghidra.app.plugin.core.strings;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.Map.Entry;
import java.util.function.Function;

import generic.jar.ResourceFile;
import ghidra.app.services.*;

/**
 * A {@link StringValidatorService} that uses precomputed trigram frequencies from
 * a ".sng" model file to score strings.
 */
public class TrigramStringValidator implements StringValidatorService {
	/**
	 * Remove this flag when the trigram model thresholds have been recalculated 
	 */
	@Deprecated(forRemoval = true, since = "10.3")
	private static final boolean PRESERVE_BUG_SKIP_TRIGRAM = true;

	// "Bad" log to be used as default score when we know the string is bad
	private static final double DEFAULT_LOG_VALUE = -20d;
	private static final double INVALID_THRESHOLD = 10.0;

	public static TrigramStringValidator read(ResourceFile f) throws IOException {
		return readModel(f);
	}

	private ResourceFile sourceFile;
	private Map<Trigram, Double> trigramLogs;
	private long totalNumTrigrams;
	private Function<String, String> modelValueTransformer;
	private double[] thresholds;	// for string lengths [4..nn]

	public TrigramStringValidator(Map<Trigram, Double> trigramLogs, long totalNumTrigrams,
			Function<String, String> modelValueTransformer, double[] thresholds,
			ResourceFile sourceFile) {
		this.trigramLogs = trigramLogs;
		this.totalNumTrigrams = totalNumTrigrams;
		this.modelValueTransformer = modelValueTransformer;
		this.thresholds = thresholds;
		this.sourceFile = sourceFile;
	}

	public ResourceFile getSourceFile() {
		return sourceFile;
	}

	@Override
	public String getValidatorServiceName() {
		return "ngram";
	}

	@Override
	public StringValidityScore getStringValidityScore(StringValidatorQuery query) {
		String transformedString = modelValueTransformer.apply(query.stringValue());
		double score = DEFAULT_LOG_VALUE;
		int trigramCount = 0;

		StringTrigramIterator it = Trigram.iterate(transformedString);
		if (it.hasNext()) {
			double missingTrigramScore = Math.log10(1d / totalNumTrigrams);
			score = 0;
			for (; it.hasNext();) {
				Trigram trigram = it.next();
				trigramCount++;
				if (PRESERVE_BUG_SKIP_TRIGRAM && trigramCount == 2) {
					// compatibility hack to replicate trigram bug in old code
					continue;
				}
				Double logProb = trigramLogs.get(trigram);
				if (logProb == null) {
					logProb = missingTrigramScore;
				}
				score += logProb;
			}
			score = score / trigramCount;
		}

		return new StringValidityScore(query.stringValue(), transformedString, score,
			getThresholdForStringOfLength(trigramCount));
	}

	public long getTotalNumTrigrams() {
		return totalNumTrigrams;
	}


	public Iterator<String> dumpModel() {
		return trigramLogs.keySet()
				.stream()
				.sorted()
				.map(trigram -> "%s=%s".formatted(trigram.toCharSeq(), trigramLogs.get(trigram)))
				.iterator();
	}

	private double getThresholdForStringOfLength(int len) {
		int index = len - 4;
		if (index < 0) {
			return INVALID_THRESHOLD;
		}
		if (index >= thresholds.length) {
			index = thresholds.length - 1;
		}
		return thresholds[index];
	}

	//---------------------------------------------------------------------------------------------

	private static TrigramStringValidator readModel(ResourceFile sourceFile) throws IOException {
		Map<Trigram, Integer> counts = new HashMap<>();
		long totalTrigrams = 0;
		String modelType = null;
		double[] thresholds = null;
		int symbolSize = 128; // default
		int lineNum = 0;
		boolean inFileHeaderSection = true;

		String currString = "";
		try (BufferedReader br = new BufferedReader(
			new InputStreamReader(sourceFile.getInputStream(), StandardCharsets.UTF_8))) {
			while ((currString = br.readLine()) != null) {
				lineNum++;
				if (currString.isBlank()) {
					continue;
				}
				if (inFileHeaderSection && currString.startsWith("#")) {
					String[] headerFields = parseHeaderLine(currString.substring(1).trim());
					if (headerFields != null) {
						switch (headerFields[0]) {
							case "Model Type":
								modelType = headerFields[1];
								break;
							case "Thresholds":
								thresholds = parseThresholds(headerFields[1]);
								break;
							case "Symbol Size":
								symbolSize = Integer.parseInt(headerFields[1]);
								break;
						}
					}
					continue;
				}

				inFileHeaderSection = false;

				String[] lineParts = currString.split("\\t");
				if (lineParts.length != 4) {
					throw new IOException("Invalid field count in ngram %s:%d: %s"
							.formatted(sourceFile.getName(), lineNum, currString));
				}

				Trigram trigram = Trigram.fromStringRep(lineParts[0], lineParts[1], lineParts[2]);
				int currCount = Integer.parseInt(lineParts[3]);

				int[] codePoints = trigram.codePoints();
				if (codePoints[1] == 0 || (codePoints[0] == 0 && codePoints[2] == 0)) {
					// if invalid combination of start-of-string, end-of-string markers
					continue;
				}

				counts.merge(trigram, currCount, (oldVal, newVal) -> oldVal + newVal);
				totalTrigrams += currCount;
			}

			// fixup missing trigram elements
			int trigramEntryCount = counts.size();

			// fully populated trigram mappings would be symbolsize^3, but due to quirk of old
			// code, we also have the special start-of-string and end-of-string doublets to count.
			int expectedEntryCount = // symbolSize^3 + (symbolSize^2)*2
				(symbolSize * symbolSize * symbolSize) + (symbolSize * symbolSize * 2);

			totalTrigrams += (expectedEntryCount - trigramEntryCount);

			Map<Trigram, Double> logProb = calculateLogProbs(counts, totalTrigrams);
			modelType = Objects.requireNonNullElse(modelType, "");
			Function<String, String> transformer = getStringTransformer(modelType);

			// normalize whitespace (in addition to whatever the transformer does)
			transformer = transformer
					.andThen(s -> s.trim().replaceAll(" {2,}", " ").replaceAll("\t{2,}", "\t"));

			return new TrigramStringValidator(logProb, totalTrigrams, transformer, thresholds,
				sourceFile);
		}
		catch (NumberFormatException nfe) {
			throw new IOException(
				"Error parsing string ngram %s:%d: %s".formatted(sourceFile.getName(), lineNum,
					currString));
		}
	}

	private static Function<String, String> getStringTransformer(String modelTypeName) {
		Function<String, String> transformer = switch (modelTypeName) {
			case "lowercase" -> String::toLowerCase;
			default -> Function.identity();
		};
		return transformer;
	}

	private static String[] parseHeaderLine(String s) {
		int colon = s.indexOf(':');
		return colon > 0
				? new String[] { s.substring(0, colon).trim(), s.substring(colon + 1).trim() }
				: null;
	}

	private static double[] parseThresholds(String s) {
		String[] parts = s.split(",");
		double[] results = new double[parts.length];
		for (int i = 0; i < parts.length; i++) {
			String thresholdValStr = parts[i];
			double d = Double.parseDouble(thresholdValStr.trim());
			results[i] = d;
		}
		return results;
	}

	private static Map<Trigram, Double> calculateLogProbs(Map<Trigram, Integer> counts,
			long totalTrigrams) {

		double totalTrigramsD = totalTrigrams;
		Map<Trigram, Double> logTrigrams = new HashMap<>();
		for (Entry<Trigram, Integer> entry : counts.entrySet()) {
			Trigram trigram = entry.getKey();
			Integer count = entry.getValue();
			logTrigrams.put(trigram, Math.log10(count / totalTrigramsD));
		}
		return logTrigrams;
	}

}
