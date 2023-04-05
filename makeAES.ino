//ECBモードのAES
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define NK_MAX (8) //keyの最大値(AES-256まで)
#define NR_MAX (14) //RoundKeyの最大値(AES-256まで)

enum {
  AES128 = 0, //AES128:0
  AES192, //AES128:1
  AES256, //AES128:2
};

uint8_t aes_type = AES128;  //AESのタイプ選択
const uint8_t Nb = 4; //Nb = 4byte

//ラウンド鍵を作成
struct key_round {
  uint8_t Nk;
  uint8_t Nr;
} const key_round_table[] = {
  { 4, 10 },  // AES128(0), Nk=4, Nr=10
  { 6, 12 },  // AES192(1), Nk=6, Nr=12
  { 8, 14 },  // AES256(2), Nk=8, Nr=14
};

/*S-Box表*/
const uint8_t sbox[] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

/*Inverse S-Box表*/
const uint8_t inv_sbox[] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
};

//MixColumns式
/* x^(i-1) mod x^8 + x^4 + x^3 + x + 1 */
const uint32_t rcon[] = {
  0x00000000, /* invalid */
  0x00000001, /* x^0 */
  0x00000002, /* x^1 */
  0x00000004, /* x^2 */
  0x00000008, /* x^3 */
  0x00000010, /* x^4 */
  0x00000020, /* x^5 */
  0x00000040, /* x^6 */
  0x00000080, /* x^7 */
  0x0000001B, /* x^4 + x^3 + x^1 + x^0 */
  0x00000036, /* x^5 + x^4 + x^2 + x^1 */
};

//既約多項式を法とする多項式の積を行う式
static uint8_t gmult(uint8_t a, uint8_t b)
{
  uint8_t c = 0, i, msb;

  for (i=0; i<8; i++) {
    if (b & 1)
      c ^= a;

    msb = a & 0x80; //0x80 = 128
    a <<= 1;
    if (msb)
      a ^= 0x1b; //0x1b = 27
    b >>= 1;
  }

  return c;
}

//1wordをbyte単位で左シフト ex) a3 a2 a1 a0 -> a0 a3 a2 a1
static uint32_t rot_word(uint32_t word)
{
  return word << 24 | word >> 8;
}

//S-boxによるbyte単位の置換
static uint32_t sub_word(uint32_t word)
{
  uint32_t val = word;
  uint8_t* p = (uint8_t*)&val;
  p[0] = sbox[p[0]]; p[1] = sbox[p[1]];
  p[2] = sbox[p[2]]; p[3] = sbox[p[3]];
  return val;
}

//AddRoundKey処理
static void add_round_key(uint8_t* state /*4*Nb*/, const uint32_t* w /*Nb*(Nr+1)*/)
{
  int i;
  uint32_t* s = (uint32_t*)state;
  for (i=0; i<Nb; i++) {
    s[i] ^= w[i];
  }
}

//SubBytes処理
static void sub_bytes(uint8_t* state /*4*Nb*/)
{
  int i;
  for (i=0; i<4*Nb; i++) {
    state[i] = sbox[state[i]];
    //Serial.print(state[i], HEX); Serial.print("\n");
  }
}

//InvSubBytes処理
static void inv_sub_bytes(uint8_t* state /*4*Nb*/)
{
  int i;
  for (i=0; i<4*Nb; i++) {
    state[i] = inv_sbox[state[i]];
  }
}

//ShiftRows処理
static void shift_rows(uint8_t* state /*4*Nb*/)
{
  /*
     00 04 08 12 => 00 04 08 12
     01 05 09 13 => 05 09 13 01
     02 06 10 14 => 10 14 02 06
     03 07 11 15 => 15 03 07 11
   */
  uint8_t tmp[3];
  tmp[0] = state[1];
  state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = tmp[0];
  tmp[0] = state[2]; tmp[1] = state[6];
  state[2] = state[10]; state[6] = state[14]; state[10] = tmp[0]; state[14] = tmp[1];
  tmp[0] = state[3]; tmp[1] = state[7]; tmp[2] = state[11];
  state[3] = state[15]; state[7] = tmp[0]; state[11] = tmp[1]; state[15] = tmp[2];
}

//InvShiftRows処理
static void inv_shift_rows(uint8_t* state /*4*Nb*/)
{
  /*
     00 04 08 12 => 00 04 08 12
     01 05 09 13 => 13 01 05 09
     02 06 10 14 => 10 14 02 06
     03 07 11 15 => 07 11 15 03
   */
  uint8_t tmp[3];
  tmp[0] = state[13];
  state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = tmp[0];
  tmp[0] = state[14]; tmp[1] = state[10];
  state[14] = state[6]; state[10] = state[2]; state[6] = tmp[0]; state[2] = tmp[1];
  tmp[0] = state[15]; tmp[1] = state[11]; tmp[2] = state[7];
  state[15] = state[3]; state[11] = tmp[0]; state[7] = tmp[1]; state[3] = tmp[2];
}

//MixColumns処理
static void mix_columns(uint8_t* state /*4*Nb*/)
{
  int i;
  uint8_t tmp[4], *s = state;

  for (i=0; i<Nb; i++) {
    tmp[0] = gmult(0x02, s[0]) ^ gmult(0x03, s[1]) ^             s[2]  ^             s[3];
    tmp[1] =             s[0]  ^ gmult(0x02, s[1]) ^ gmult(0x03, s[2]) ^             s[3];
    tmp[2] =             s[0]  ^             s[1]  ^ gmult(0x02, s[2]) ^ gmult(0x03, s[3]);
    tmp[3] = gmult(0x03, s[0]) ^             s[1]  ^             s[2]  ^ gmult(0x02, s[3]);
    memcpy(s, tmp, 4);
    s += 4;
  }
}

//InvMixColumns処理
static void inv_mix_columns(uint8_t* state /*4*Nb*/)
{
  int i;
  uint8_t tmp[4], *s = state;

  for (i=0; i<Nb; i++) {
    tmp[0] = gmult(0x0e, s[0]) ^ gmult(0x0b, s[1]) ^ gmult(0x0d, s[2]) ^ gmult(0x09, s[3]);
    tmp[1] = gmult(0x09, s[0]) ^ gmult(0x0e, s[1]) ^ gmult(0x0b, s[2]) ^ gmult(0x0d, s[3]);
    tmp[2] = gmult(0x0d, s[0]) ^ gmult(0x09, s[1]) ^ gmult(0x0e, s[2]) ^ gmult(0x0b, s[3]);
    tmp[3] = gmult(0x0b, s[0]) ^ gmult(0x0d, s[1]) ^ gmult(0x09, s[2]) ^ gmult(0x0e, s[3]);
    memcpy(s, tmp, 4);
    s += 4;
  }
}

//keyや暗号文などの数値を表示させる関数, wordにkeyなどが入る
static void print_Nwords(const uint32_t* word, int N)
{
  int i;

  for (i=0; i<N; i++) {
    uint8_t* p = (uint8_t*)(word+i);
    Serial.print(p[0], HEX);
    Serial.print(",");
    Serial.print(p[1], HEX);
    Serial.print(",");
    Serial.print(p[2], HEX);
    Serial.print(",");
    Serial.print(p[3], HEX);
    Serial.print(",");
  }
}

//鍵スケジュール→ラウンド鍵として拡張
extern void key_expansion(const uint32_t* key /*Nk*/, uint32_t* w /*Nb*(Nr+1)*/)
{
  int i;
  uint8_t Nr = key_round_table[aes_type].Nr;
  uint8_t Nk = key_round_table[aes_type].Nk;

  memcpy(w, key, Nk*4);
  for (i=Nk; i<Nb*(Nr+1); i++) {
    uint32_t temp = w[i-1];
    if (i%Nk == 0) {
      temp = sub_word(rot_word(temp)) ^ rcon[i/Nk];
    } else if (6<Nk && i%Nk == 4) {
      temp = sub_word(temp);
    }
    w[i] = w[i-Nk] ^ temp;
  }
}

//暗号化
extern void cipher(const uint8_t* in /*4*Nb*/, uint8_t* out /*4*Nb*/, const uint32_t* w /*Nb*(Nr+1)*/)
{
  int i;
  uint8_t Nr = key_round_table[aes_type].Nr, *state = out;

  memcpy(state, in, 4*Nb);
  add_round_key(state, &w[0]);
  for (i=1; i<Nr; i++) {
    sub_bytes(state);
    shift_rows(state);
    mix_columns(state);
    add_round_key(state, &w[Nb*i]);
  }
  sub_bytes(state);
  shift_rows(state);
  add_round_key(state, &w[Nb*Nr]);
}

//復号
extern void inv_cipher(const uint8_t* in /*4*Nb*/, uint8_t* out /*4*Nb*/, const uint32_t* w /*Nb*(Nr+1)*/)
{
  int i;
  uint8_t Nr = key_round_table[aes_type].Nr, *state = out;

  memcpy(state, in, 4*Nb);
  add_round_key(state, &w[Nb*Nr]);
  for (i=Nr-1; 1<=i; i--) {
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, &w[Nb*i]);
    inv_mix_columns(state);
  }
  inv_shift_rows(state);
  inv_sub_bytes(state);
  add_round_key(state, &w[0]);
}

//暗号化と復号を同時に処理する関数
static void cipher_and_inv_cipher(const uint32_t* key, const uint32_t* in)
{
  uint32_t w[Nb*(NR_MAX+1)], out[4], tmp[4];
  uint8_t Nk = key_round_table[aes_type].Nk;

  Serial.print("Cipher Key = "); print_Nwords(key, Nk); Serial.print("\n");
  key_expansion(key, w);
  Serial.print("Input      = "); print_Nwords(in, 4); Serial.print("\n");
  cipher((uint8_t*)in, (uint8_t*)out, w);
  Serial.print("Output     = "); print_Nwords(out, 4); Serial.print("\n");
  inv_cipher((uint8_t*)out, (uint8_t*)tmp, w);
  Serial.print("Input(Inv) = "); print_Nwords(tmp, 4); Serial.print("\n");
  Serial.print("\n");
}

//それぞれシリアルモニタへ出力
void setup() {
  Serial.begin(9600); //9600ポートに接続
  //uint8_t key[NK_MAX*4], in[Nb*4], i;

//テストベクタ1
  uint8_t key[NK_MAX*4] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  uint8_t in[Nb*4] = {0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255};  
  uint8_t i;
  //ans = 69,C4,E0,D8,6A,7B,4,30,D8,CD,B7,80,70,B4,C5,5A

  //Test Vector1
  //sample_key   = "000102030405060708090a0b0c0d0e0f";
  //sample_input = "00112233445566778899aabbccddeeff";
  //sample_cipher= "69c4e0d86a7b0430d8cdb78070b4c55a";

  //Test Vector2
  //sample_key   = "2b7e151628aed2a6abf7158809cf4f3c";
  //sample_input = "6bc1bee22e409f96e93d7e117393172a";
  //sample_cipher= "3ad77bb40d7a3660a89ecaf32466ef97";

/*
//未知な鍵（ランダム値）の入力
  //ランダムkeyの設定
  for (i=0; i<NK_MAX*4; i++) {
    key[i] = (uint8_t)(random(255));
  }
  //ランダムinput(平文)の設定
  for (i=0; i<Nb*4; i++) {
    in[i] = (uint8_t)(random(255));
  }
*/

/*
//デフォルト値
  //keyの設定
  for (i=0; i<NK_MAX*4; i++) {
    key[i] = i;
  }
  //input(平文)の設定
  for (i=0; i<Nb*4; i++) {
    in[i] = i << 4 | i;
  }
*/

  Serial.print("AES-128\n");
  aes_type = AES128;
  cipher_and_inv_cipher((uint32_t*)key, (uint32_t*)in);

  Serial.print("AES-192\n");
  aes_type = AES192;
  cipher_and_inv_cipher((uint32_t*)key, (uint32_t*)in);

  Serial.print("AES-256\n");
  aes_type = AES256;
  cipher_and_inv_cipher((uint32_t*)key, (uint32_t*)in);
}

void loop() {
  // put your main code here, to run repeatedly:

}
