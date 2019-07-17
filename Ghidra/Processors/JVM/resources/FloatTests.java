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
class FloatTests{

    public double float2double(float x){
        return (double) x;
    }
 
    public int float2int(float x){
        return (int) x;
    }

    public long float2long(float x){
        return (long) x;
    }

   public float floatAdd(float x, float y){
       return x+y;
   }

   public int floatComparison1(float x, float y){
       if (x < y){
           return 1;
       }
       return 0;
   }

   public int floatComparison2(float x, float y){
       if (x==y) {
           return 1;
       }
       return 0;
   }

   public int floatComparison3(float x, float y){
      if (x > y){
          return 1;
      }
      return 0;
   }

   public float return0(){
       return 0.0f;
   }

   public float return1(){
       return 1.0f;
   }

   public float return2(){
       return 2.0f;
   }

   public float divTest(float x, float y){
       return x/y;
   }
   
   public float mulTest(float x, float y){
       return x * y;
   }

   public float negTest(float x){
       return -x;
   }

   public float remText(float x, float y){
      return x % y;
   }

   public float subTest(float x, float y){
       return x - y;
   }
}
