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
#include "lsh.h"

#define LSH_HASHBASE 0xD7E6A299

static char hash_signtable[512];

static void hash_int_fft_16(int32 *arr)

{
  int32 x,y;
  
  x = arr[0]; y = arr[8]; arr[0] = x + y; arr[8] = x - y;
  x = arr[1]; y = arr[9]; arr[1] = x + y; arr[9] = x - y;
  x = arr[2]; y = arr[10]; arr[2] = x + y; arr[10] = x - y;
  x = arr[3]; y = arr[11]; arr[3] = x + y; arr[11] = x - y;
  x = arr[4]; y = arr[12]; arr[4] = x + y; arr[12] = x - y;
  x = arr[5]; y = arr[13]; arr[5] = x + y; arr[13] = x - y;
  x = arr[6]; y = arr[14]; arr[6] = x + y; arr[14] = x - y;
  x = arr[7]; y = arr[15]; arr[7] = x + y; arr[15] = x - y;

  x = arr[0]; y = arr[4]; arr[0] = x + y; arr[4] = x - y;
  x = arr[1]; y = arr[5]; arr[1] = x + y; arr[5] = x - y;
  x = arr[2]; y = arr[6]; arr[2] = x + y; arr[6] = x - y;
  x = arr[3]; y = arr[7]; arr[3] = x + y; arr[7] = x - y;
  x = arr[8]; y = arr[12]; arr[8] = x + y; arr[12] = x - y;
  x = arr[9]; y = arr[13]; arr[9] = x + y; arr[13] = x - y;
  x = arr[10]; y = arr[14]; arr[10] = x + y; arr[14] = x - y;
  x = arr[11]; y = arr[15]; arr[11] = x + y; arr[15] = x - y;

  x = arr[0]; y = arr[2]; arr[0] = x + y; arr[2] = x - y;
  x = arr[1]; y = arr[3]; arr[1] = x + y; arr[3] = x - y;
  x = arr[4]; y = arr[6]; arr[4] = x + y; arr[6] = x - y;
  x = arr[5]; y = arr[7]; arr[5] = x + y; arr[7] = x - y;
  x = arr[8]; y = arr[10]; arr[8] = x + y; arr[10] = x - y;
  x = arr[9]; y = arr[11]; arr[9] = x + y; arr[11] = x - y;
  x = arr[12]; y = arr[14]; arr[12] = x + y; arr[14] = x - y;
  x = arr[13]; y = arr[15]; arr[13] = x + y; arr[15] = x - y;

  x = arr[0]; y = arr[1]; arr[0] = x + y; arr[1] = x - y;
  x = arr[2]; y = arr[3]; arr[2] = x + y; arr[3] = x - y;
  x = arr[4]; y = arr[5]; arr[4] = x + y; arr[5] = x - y;
  x = arr[6]; y = arr[7]; arr[6] = x + y; arr[7] = x - y;
  x = arr[8]; y = arr[9]; arr[8] = x + y; arr[9] = x - y;
  x = arr[10]; y = arr[11]; arr[10] = x + y; arr[11] = x - y;
  x = arr[12]; y = arr[13]; arr[12] = x + y; arr[13] = x - y;
  x = arr[14]; y = arr[15]; arr[14] = x + y; arr[15] = x - y;
}

static void hash_double_fft_16(double *arr)

{
  double x,y;
  
  x = arr[0]; y = arr[8]; arr[0] = x + y; arr[8] = x - y;
  x = arr[1]; y = arr[9]; arr[1] = x + y; arr[9] = x - y;
  x = arr[2]; y = arr[10]; arr[2] = x + y; arr[10] = x - y;
  x = arr[3]; y = arr[11]; arr[3] = x + y; arr[11] = x - y;
  x = arr[4]; y = arr[12]; arr[4] = x + y; arr[12] = x - y;
  x = arr[5]; y = arr[13]; arr[5] = x + y; arr[13] = x - y;
  x = arr[6]; y = arr[14]; arr[6] = x + y; arr[14] = x - y;
  x = arr[7]; y = arr[15]; arr[7] = x + y; arr[15] = x - y;

  x = arr[0]; y = arr[4]; arr[0] = x + y; arr[4] = x - y;
  x = arr[1]; y = arr[5]; arr[1] = x + y; arr[5] = x - y;
  x = arr[2]; y = arr[6]; arr[2] = x + y; arr[6] = x - y;
  x = arr[3]; y = arr[7]; arr[3] = x + y; arr[7] = x - y;
  x = arr[8]; y = arr[12]; arr[8] = x + y; arr[12] = x - y;
  x = arr[9]; y = arr[13]; arr[9] = x + y; arr[13] = x - y;
  x = arr[10]; y = arr[14]; arr[10] = x + y; arr[14] = x - y;
  x = arr[11]; y = arr[15]; arr[11] = x + y; arr[15] = x - y;

  x = arr[0]; y = arr[2]; arr[0] = x + y; arr[2] = x - y;
  x = arr[1]; y = arr[3]; arr[1] = x + y; arr[3] = x - y;
  x = arr[4]; y = arr[6]; arr[4] = x + y; arr[6] = x - y;
  x = arr[5]; y = arr[7]; arr[5] = x + y; arr[7] = x - y;
  x = arr[8]; y = arr[10]; arr[8] = x + y; arr[10] = x - y;
  x = arr[9]; y = arr[11]; arr[9] = x + y; arr[11] = x - y;
  x = arr[12]; y = arr[14]; arr[12] = x + y; arr[14] = x - y;
  x = arr[13]; y = arr[15]; arr[13] = x + y; arr[15] = x - y;

  x = arr[0]; y = arr[1]; arr[0] = x + y; arr[1] = x - y;
  x = arr[2]; y = arr[3]; arr[2] = x + y; arr[3] = x - y;
  x = arr[4]; y = arr[5]; arr[4] = x + y; arr[5] = x - y;
  x = arr[6]; y = arr[7]; arr[6] = x + y; arr[7] = x - y;
  x = arr[8]; y = arr[9]; arr[8] = x + y; arr[9] = x - y;
  x = arr[10]; y = arr[11]; arr[10] = x + y; arr[11] = x - y;
  x = arr[12]; y = arr[13]; arr[12] = x + y; arr[13] = x - y;
  x = arr[14]; y = arr[15]; arr[14] = x + y; arr[15] = x - y;
}

/*
 * This is a precalculated table for generating dotproducts with the random family of vectors directly
 * The first vector r_0 is expressed as a hashing function on the dimension index and the other vectors
 * are derived from r_0 using an FFT.  The table is formed by precalculating the FFT on basis vectors in this table
 */
void lsh_setup_signtable(void)

{
  int32 i,j;
  int32 arr[16];
  char *hibit0ptr;
  char *hibit1ptr;

  for(i=0;i<16;++i) {		/* For each 4-bit position */
    hibit0ptr = hash_signtable + i * 16;
    hibit1ptr = hash_signtable + (i+16) * 16;
    for(j=0;j<16;++j)
      arr[j] = 0;

    arr[ i ] = 1;
    hash_int_fft_16(arr);
    for(j=0;j<16;++j) {
      if (arr[j] > 0) {
	hibit0ptr[j] = '+';
	hibit1ptr[j] = '-';
      }
      else {
	hibit0ptr[j] = '-';
	hibit1ptr[j] = '+';
      }
    }
  }
}

/*
 * Generate a dot product of the hash vector in -vec- with a random family of 16 vectors, { r }
 * r_0 is a randomly generated set of +1 -1 coefficients across all the dimensions (indexed by uint32 vec[i].hash)
 *   The coefficient is calculated as a hashing function from the seed -hashcur- and the index (vec[i].hash),
 *   so it should be balanced between +1 and -1.
 * All the other vectors are generated from an FFT of r_0.  This allows the dotproduct with vec to be calculated
 *   using an FFT if -vec- has many non-zero coefficients.  If -vec- has only a few non-zero coefficients,
 *   the dotproduct if calculated with each vector in the family directly for better efficiency.
 * The resulting dotproducts are converted into a 16-long bitvector based on the sign of the dotproduct and
 *   placed in -bucket-
 */
static uint32 hash_16_dotproduct(uint32 bucket,LSH_ITEM *vec,uint32 vecsize,uint32 hashcur,uint32 vecsizeupper)

{
  uint32 i,j;
  uint32 rownum;
  char *signptr;
  double res[16];

  for(i=0;i<16;++i)
    res[i] = 0.0;		/* Initialize the dotproduct results to zero */

  if (vecsize < vecsizeupper) {	/* If there are a small number of non-zero coefficients in -vec- */
    for(i=0;i<vecsize;++i) {
      rownum = vec[i].hash ^ hashcur; /* Calculate the rest of the r_0 hashing function*/
      rownum = (rownum * 1103515245) + 12345;
      rownum = (rownum>>24)&0x1f;
      signptr = hash_signtable + rownum * 16;
      for(j=0;j<16;++j) {	/* Based on the precalculated coeff table calculate this portion of dotproduct */
	if (signptr[j] == '+')
	  res[j] += vec[i].coeff; /* Dot product with +1 coeff */
	else
	  res[j] -= vec[i].coeff; /* Dot product with -1 coeff */
      }
    }
  }
  else {			/* If we have many non-zero coeffs in -vec- */
    for(i=0;i<vecsize;++i) {
      rownum = vec[i].hash ^ hashcur; /* Calculate the rest of the r_0 hashing function*/
      rownum = (rownum * 1103515245) + 12345;
      rownum = (rownum>>24)&0x1f;
      if (rownum < 0x10)	/* Set-up for the FFT */
	res[rownum] += vec[i].coeff;
      else
	res[rownum&0xf] -= vec[i].coeff;
    }
    hash_double_fft_16(res);	/* Calculate the remaining dotproducts be performing FFT */
  }

  for(i=0;i<16;++i) {		/* Convert the dotproduct results to a bitvector */
    bucket <<= 1;
    if (res[i] > 0.0)
      bucket |= 1;
  }
  return bucket;
}

void lsh_generate_binids(uint32 *res,LSH_ITEM *vec,uint32 vecsize)

{
  uint32 bucket = 0;
  int32 bucketcnt = 0;
  int32 i,bitsleft;
  uint32 curid;
  uint32 mask,val;
  uint32 hashbase = LSH_HASHBASE;

  for(i=0;i<lsh_L;++i) {
    curid = i;		/* Tack-on bits that indicate the particular table this binid belongs to */
    bitsleft = lsh_k;
    do {
      if (bucketcnt == 0) {
	hashbase = (hashbase * 1103515245) + 12345;
	bucket = hash_16_dotproduct(bucket,vec,vecsize,hashbase,5);
	bucketcnt += 16;
      }
      if (bucketcnt >= bitsleft) {
	curid <<= bitsleft;
	mask = 1;
	mask = (mask << bitsleft)-1;
	val = bucket >> (bucketcnt - bitsleft);
	curid |= (val & mask);
	bucketcnt -= bitsleft;
	bitsleft = 0;
      }
      else {
	curid <<= bucketcnt;
	mask = 1;
	mask = (mask << bucketcnt)-1;
	curid |= (bucket & mask);
	bitsleft -= bucketcnt;
	bucketcnt = 0;
      }
    } while(bitsleft > 0);
    res[ i ] = curid;
  }
}

void lsh_generate_binids_datum(Datum *res,LSH_ITEM *vec,uint32 vecsize)

{
  uint32 bucket = 0;
  int32 bucketcnt = 0;
  int32 i,bitsleft;
  uint32 curid;
  uint32 mask,val;
  uint32 hashbase = LSH_HASHBASE;

  for(i=0;i<lsh_L;++i) {
    curid = i;		/* Tack-on bits that indicate the particular table this binid belongs to */
    bitsleft = lsh_k;
    do {
      if (bucketcnt == 0) {
	hashbase = (hashbase * 1103515245) + 12345;
	bucket = hash_16_dotproduct(bucket,vec,vecsize,hashbase,5);
	bucketcnt += 16;
      }
      if (bucketcnt >= bitsleft) {
	curid <<= bitsleft;
	mask = 1;
	mask = (mask << bitsleft)-1;
	val = bucket >> (bucketcnt - bitsleft);
	curid |= (val & mask);
	bucketcnt -= bitsleft;
	bitsleft = 0;
      }
      else {
	curid <<= bucketcnt;
	mask = 1;
	mask = (mask << bucketcnt)-1;
	curid |= (bucket & mask);
	bitsleft -= bucketcnt;
	bucketcnt = 0;
      }
    } while(bitsleft > 0);
    res[ i ] = Int32GetDatum((int32)curid);
  }
}
