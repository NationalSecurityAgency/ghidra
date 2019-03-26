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
class LVALong{


    long test1(long a, long b, long c, long d){
        long w = a + b;
        long x = c + d;
        long y = test2(w);
        long z = test2(x);
        return y+z;
     }


    long test1_1(long a, long b, long c, long d){
        long w = a + b;
        long y = test2(w);
        long x = a + b;
        long z = test2(x);
        return y+z;
     }

    long test1_2(long a, long b){
        long w = a + b;
        long z = test2(w);
        return z;
     }

    int test1_2_int(int a, int b){
        int w = a + b;
        int z = test2int(w);
        return z;
     }
    
    
    long test1_2_long(int a, int b){
        long w = a + b;
        long z = test2(w);
        return z;
     }


    long test2( long a){
        return a+a;
    }

    int test2int(int a){
        return a+a;
    }

    long test3(long a, long b, long c, long d){
        long w = a + b;
        long x = c + d;
        long y = a + c;
        long z = b + d;
        return w+x+y+z;
     }

    long mixed1(long a, int b){
        long x = a + (long) b;
        return x;
}

   long mixed2(int b, long a){
       long x = a + (long) b;
       return x;
    }

    long mixed3(int a, long b, int c, long d){
        long x = (long) a;
        long y = (long) c;
        return x + y + b + d;
    }
}

