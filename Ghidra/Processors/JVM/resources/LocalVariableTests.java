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
class LocalVariableTests{

   public boolean booleanTest(boolean a, boolean b){
       boolean one = a;
       boolean two = b;
       return one || two;
   }

   public byte byteTest(byte a, byte b){
       byte one = a;
       byte two = b;
       return (byte) (one + two); 
   }

   public char charTest(char a, char b){
       char one = a;
       char two = b;
       return (char) (one + two); 
   }

   public short shortTest(short a, short b){
       short one = a;
       short two = b;
       return (short) (one + two); 
   }

   public int intTest(int a, int b){
       int one = a;
       int two = b;
       int sum = one + two;
       if (sum % 2 == 0){
           return 1;
       }
       return one + two; 
   }

   public float floatTest(float a, float b){
       float one = a;
       float two = b;
       return one + two; 
   }

   public Integer refTest(Integer a, Integer b){
       Integer one = a;
       Integer two = b;
       return one + two; 
   }


   public long longTest(long a, long b){
       long one = a;
       long two = b;
       return one + two; 
   }

   public double doubleTest(double a, double b){
       double one = a;
       double two = b;
       return one + two; 
   }
   
}
