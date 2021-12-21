// @file  simple-integers-bgvrns.cpp - Simple example for BGVrns (integer
// arithmetic).
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT))
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "palisade.h"

using namespace lbcrypto;

#define Tasdf std::shared_ptr<CiphertextImpl<DCRTPoly>>

void dp(const CryptoContext<DCRTPoly> &cryptoContext,
        const Tasdf &orig,
        const LPKeyPair<DCRTPoly> &keyPair) {
    //Plaintext p;
    //cryptoContext->Decrypt(keyPair.secretKey, orig,
    //                       &p);
    //std::cout << p << std::endl;
}

Tasdf reduce(const CryptoContext<DCRTPoly> &cryptoContext,
                                             const Tasdf &orig,
             const LPKeyPair<DCRTPoly> &keyPair) {
  std::vector<Tasdf> arr;
  arr.push_back(orig);
  for (int i = 1; i < 8; ++i) {
    auto a = cryptoContext->EvalAtIndex(orig, i);
    arr.push_back(a);
    dp(cryptoContext, a, keyPair);
  }
  auto a = cryptoContext->EvalMultMany(arr);
  return a;
}



void asdf(const CryptoContext<DCRTPoly> &cryptoContext,
          const LPKeyPair<DCRTPoly> &keyPair,
          const std::vector<int64_t> &pass) {
  std::vector<int64_t> neg_upper;
  std::vector<int64_t> neg_lower;
  std::vector<int64_t> pos_upper;
  std::vector<int64_t> pos_lower;
  for (int i = 0; i < (int)pass.size(); ++i) {
    neg_upper.push_back(-155);
    neg_lower.push_back(-219);
    pos_upper.push_back(5850);
    pos_lower.push_back(11834);
  }

  Plaintext password = cryptoContext->MakePackedPlaintext(pass);
  Plaintext pneg_upper = cryptoContext->MakePackedPlaintext(neg_upper);
  Plaintext pneg_lower = cryptoContext->MakePackedPlaintext(neg_lower);
  Plaintext ppos_upper = cryptoContext->MakePackedPlaintext(pos_upper);
  Plaintext ppos_lower = cryptoContext->MakePackedPlaintext(pos_lower);

  // The encoded vectors are encrypted
  auto cp = cryptoContext->Encrypt(keyPair.publicKey, password);


  // shift right and sub for repeated char, 0 if repeated
  auto cp_shift_right = cryptoContext->EvalAtIndex(cp, -1);
  auto cp_shift_sub = cryptoContext->EvalSub(cp, cp_shift_right);



  // 0x41 -> 0x5A For upper, x^2 - 155 x + 5850
  // 0x61 -> 0x7A For lower, x^2 - 219 x + 11834
  // simple polynomial for character classes, negative if match

  auto cp_square = cryptoContext->EvalMult(cp, cp); // depth 1
  auto cp_upper_mul = cryptoContext->EvalMult(cp, pneg_upper); // depth 1
  auto cp_lower_mul = cryptoContext->EvalMult(cp, pneg_lower);

  auto cp_upper_sum1 = cryptoContext->EvalAdd(cp_upper_mul, cp_square); // depth 2
  auto cp_lower_sum1 = cryptoContext->EvalAdd(cp_lower_mul, cp_square);

  auto cp_upper_sum2 = cryptoContext->EvalAdd(cp_upper_sum1, ppos_upper); // depth 3
  auto cp_lower_sum2 = cryptoContext->EvalAdd(cp_lower_sum1, ppos_lower);

  auto mulaccum1 = reduce(cryptoContext, cp_shift_sub, keyPair);
  auto mulaccum2 = reduce(cryptoContext, cp_upper_sum2, keyPair);
  auto mulaccum3 = reduce(cryptoContext, cp_lower_sum2, keyPair);

  // Sample Program: Step 5 - Decryption

  // Decrypt the result of additions
  Plaintext repeatedCharPlain;
  cryptoContext->Decrypt(keyPair.secretKey, mulaccum1,
                         &repeatedCharPlain);
  repeatedCharPlain->SetLength(pass.size());

  Plaintext upperPlain;
  cryptoContext->Decrypt(keyPair.secretKey, mulaccum2,
                         &upperPlain); // great design - crashed with undefined instruction if use repeatedCharPlain
  upperPlain->SetLength(pass.size());

  Plaintext lowerPlain;
  cryptoContext->Decrypt(keyPair.secretKey, mulaccum3,
                         &lowerPlain);
  lowerPlain->SetLength(pass.size());


  //std::cout << "Plaintext     : " << password << std::endl;
  //std::cout << "Result part 1: " << repeatedCharPlain << std::endl;
  //std::cout << "Repeated plain: " << repeatedCharPlain << std::endl;
  //std::cout << "Upper plain   : " << upperPlain << std::endl; // n.b. doesn't work because overflowsxs
//  std::cout << "Result part 3: " << lowerPlain << std::endl;
  //std::cout << std::endl;
}

int main() {
  // Sample Program: Step 1 - Set CryptoContext

  // Set the main parameters
  int plaintextModulus = 65537;
  float sigma = 3.2;
  SecurityLevel securityLevel = HEStd_128_classic;
  int depth = 9;

  // Instantiate the crypto context
  CryptoContext<DCRTPoly> cryptoContext =
     CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(
         depth, plaintextModulus, securityLevel, sigma, depth, OPTIMIZED, BV);
     // CryptoContextFactory<DCRTPoly>::genCryptoContextNull(2048, plaintextModulus);

  // Enable features that you wish to use
  cryptoContext->Enable(ENCRYPTION);
  cryptoContext->Enable(SHE);
  cryptoContext->Enable(LEVELEDSHE);

  // Sample Program: Step 2 - Key Generation

  // Initialize Public Key Containers
  LPKeyPair<DCRTPoly> keyPair;

  // Generate a public/private key pair
  keyPair = cryptoContext->KeyGen();

  // Generate the relinearization key
  cryptoContext->EvalMultKeyGen(keyPair.secretKey);

  // Generate the rotation evaluation keys
  cryptoContext->EvalAtIndexKeyGen(keyPair.secretKey, {-1, 1, 2, 3, 4, 5, 6, 7});

  // Sample Program: Step 3 - Encryption

  std::vector<int64_t> pass1 = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
  std::vector<int64_t> pass2 = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
  std::vector<int64_t> pass3 = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'};
  std::vector<int64_t> pass4 = {'A', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
  // First plaintext vector is encoded
  for (int i = 0; i < 10; ++i) {
    asdf(cryptoContext, keyPair, pass1);
    asdf(cryptoContext, keyPair, pass2);
    asdf(cryptoContext, keyPair, pass3);
    asdf(cryptoContext, keyPair, pass4);
  }
  // program goal:
  // homomorphic password validator
  // requirements: one lowercase, one uppercase
  // no repeated characters
  // going to restrict length to 8 chars, would pad

  return 0;
}
