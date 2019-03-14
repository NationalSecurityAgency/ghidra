/* ###
 * IP: GHIDRA
 * REVIEWED: YES
 * NOTE: Locality Sensitive Hashing
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
package generic.lsh;

import static java.lang.Math.PI;
import static java.lang.Math.acos;
import static java.lang.Math.pow;

import java.io.PrintStream;
import java.math.BigDecimal;
import java.math.BigInteger;

/**
 * Translated from the C++ version.
 *
 */
public class KandL {
	// Input desired tau threshold for cosine similarity,
	// P1 probability lower bound for meeting this threshold,
	// Spits out sample hash size, k and number of tables L giving
	// table size and expected query time for various data sizes (n).

	static double probOfHashMatch(double tau) {
		// Given a lower bound on cosine similarity, -tau-, calculate the probability of a random
		// projection, splitting two vectors whose similarity lies within this bound
		//
		// Pr[ h(v) = h(w) ] = 1 - \theta / pi,  where \theta is the angle between v and w
		//
		double thetabound = acos(tau);
		// taubound <= tau   =>   theta <= thetabound
		//                  =>  probofmatch = 1 -theta/pi  >=  1 -thetabound/pi
		double probbound = 1.0 - thetabound / PI;
		return probbound;
	}

	public static int memoryModelToL(LSHMemoryModel model) {
		return kToL(model.getK(), model.getTauBound(), model.getProbabilityThreshold());
	}

	public static int kToL(int k, double taubound, double probthresh) {
		double P1 = probOfHashMatch(taubound);
		// Given hash size and probability of match for a single match, calculate number of tables
		// to achieve desired probability threshold
		double prob_k_matches = pow(P1, k);
		double prob_nomatch = 1.0 - prob_k_matches;
		int L = 1;
		double prob_nomatch_n = prob_nomatch;
		while (1.0 - prob_nomatch_n < probthresh) {
			L += 1;
			prob_nomatch_n *= prob_nomatch; // Probability of no match after L tables
		}
		return L;
	}

	static double binHits(int k, int L, BigInteger n) {
		// Expected number of vectors in (one of the) same bins as query (random) vector
		BigInteger numbins = new BigInteger(new byte[] { 1 });
		numbins = numbins.shiftLeft(k);
		double hitsperbin = new BigDecimal(n).divide(new BigDecimal(numbins)).doubleValue();// Expected number of elements per bin
		double numcompare = hitsperbin * L;
		return numcompare;
	}

	static void print_result(PrintStream out, int k, int L, BigInteger n, double qt) {
		out.println(String.format("k=%d L=%d n=%s bin hits=%f k*L=%d", k, L, n.toString(), qt, k *
			L));
	}

	static void process_n(PrintStream out, BigInteger n, double taubound, double probthresh) {
		for (int k = 10; k <= 30; ++k) {
			int L = kToL(k, taubound, probthresh);
			double qt = binHits(k, L, n);
			print_result(out, k, L, n, qt);
		}
	}

	public static void main(String[] args) {
		try {
			BigInteger n = new BigInteger(args[0]);
			double taubound = Double.parseDouble(args[1]);
			double probthresh = Double.parseDouble(args[2]);
			process_n(System.out, n, taubound, probthresh);
		}
		catch (Exception e) {
			System.err.println("caught " + e.getClass().getName() + ": " + e.getLocalizedMessage());
			System.err.println("USAGE: KandL n taulowerbound probthresh");
		}
	}
}
