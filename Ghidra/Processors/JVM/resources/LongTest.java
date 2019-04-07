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
class LongTest{

		public double testl2d(long x){
				return (double) x;
		}

		public float testl2f(long x){
				return (float) x;
		}

		public int testl2i(long x){
				return (int) x;
		}

		public long testlAdd(long x, long y){
				return x + y;
		}

                public long testland(long x, long y){
                    return x & y;
                }

		public long testlcmp(long x, long y){
				if (x < y){
						return 1;
				}
				return 0;
		}

		public long test0(){
				return 0l;
		}

		public long test1(){
				return 1l;
		}

		public long testdiv(long x, long y){
				return x/y;
		}

		public long testmul(long x, long y){
				return x * y;
		}

		public long testneg(long x){
				return -x;
		}

		public long testlor(long x, long y){
				return x | y;
		}

		public long testrem(long x, long y){
				return x % y;
		}

		public long testlshl(long x, int amount){
				return x << amount;
		}

		public long testlshr(long x, int amount){
				return x >> amount;
		}

		public long testsub(long x, long y){
				return x-y;
		}

		public long testlushr(long x, int amount){
				return x >>> amount;
		}

		public long testlxor(long x, long y){
				return x ^ y;
		}

                public long testStack(long x, int y){
                    long lor = testlor(x,x);
                    if (lor == y){
                        return testlshr(x,y);
                    }
                    else{
                        return testlshr(x,y+y);
                    }
                }
}    
 


