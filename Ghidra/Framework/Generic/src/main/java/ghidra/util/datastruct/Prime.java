/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.util.datastruct;


/**
 * Class that provides a static nextPrime method that gives out prime numbers
 * that are useful in a buffer doubling strategy with all buffer sizes being prime.
 */

public final class Prime {


    private static final int[] PRIMES = {
        17, 37, 67, 131, 257,
        521, 1031, 2053, 4099, 8209, 16411, 29251, 65537,
        131101, 262147, 524309, 1048583, 2097169, 4194319, 8388617, 16777259,
        33554467, 67108879, 134217757, 268435459, 536870923, 1073741827, 2147483647

        // finer-grained table
        /*11, 37, 71, 127, 179, 257, 359, 491, 661, 887, 1181, 1553,
        2053, 2683, 3517, 4591, 6007, 7817, 10193, 13291, 17291,
        22481, 29251, 38053, 49499, 64373, 83701, 108863, 141511,
        184003, 239231, 310997, 404321, 525649, 683377, 888397,
        1154947, 1501447, 1951949, 2537501, 3298807, 4288439,
        5575001, 7247533, 9421793, 12248389, 15922903, 20699753,
        26909713, 34982639, 45477503, 59120749, 76856959, 99914123,
        129888349, 168854831, 219511301, 285364721, 370974151,
        482266423, 626946367, 815030309, 1059539417, 1377401287,
        1790621681, 2147483647
        //*/
    };


    /**
     * Finds the next prime number greater than or equal to n.
     * @param n the number from which to find the next higher prime number.
     */
    public final static int nextPrime(int n) {
        for(int i=0;i<PRIMES.length;i++) {
            if (PRIMES[i] > n) {
                return PRIMES[i];
            }
        }
        return 0;
    }
}
