// @file  advanced-real-numbers.cpp - Advanced examples for CKKS.
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, Duality Technologies Inc.
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

// Define PROFILE to enable TIC-TOC timing measurements
#define PROFILE

#include "palisade.h"

using namespace lbcrypto;

void dp(const CryptoContext<DCRTPoly> &cryptoContext,
        const shared_ptr<CiphertextImpl<DCRTPoly>> &orig,
        const LPKeyPair<DCRTPoly> &keyPair) {
  // Plaintext p;
  // cryptoContext->Decrypt(keyPair.secretKey, orig,
  //                        &p);
  // std::cout << p << std::endl;
}

int main(int argc, char *argv[]) {
  // HYBRID;

  uint32_t multDepth = 5;
  uint32_t scaleFactorBits = 50;
  uint32_t batchSize = 8;
  SecurityLevel securityLevel = HEStd_128_classic;
  // 0 means the library will choose it based on securityLevel
  uint32_t ringDimension = 0;
  CryptoContext<DCRTPoly> cc =
      CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
          multDepth, scaleFactorBits, batchSize, securityLevel, ringDimension,
          APPROXAUTO);

  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);
  // When using EXACTRESCALE, LEVELEDSHE has to be enabled because Rescale is
  // implicitly used upon multiplication.
  cc->Enable(LEVELEDSHE);

  auto keys = cc->KeyGen();
  cc->EvalMultKeyGen(keys.secretKey);

  // Input
  vector<double> x = {1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0};
  Plaintext ptxt = cc->MakeCKKSPackedPlaintext(x);
  auto c = cc->Encrypt(keys.publicKey, ptxt);
  cc->EvalSumKeyGen(keys.secretKey);
  cc->EvalMultKeyGen(keys.secretKey);
  cc->EvalAutomorphismKeyGen(keys.secretKey, {3});

  vector<double> rawfilter = {-1.0, 1.0};
  std::cout << "Input x: " << ptxt << std::endl;
  std::cout << "Filter : " << rawfilter << std::endl;

  vector<vector<double>> filters;

  for (int i = 0; i < x.size(); ++i) {
    vector<double> f;
    f.reserve(i + rawfilter.size());
    for (int j = 0; j < i; j++) {
      f.push_back(0.0);
    }
    for (int j = 0; j < rawfilter.size(); ++j) {
      f.push_back(rawfilter[j]);
    }
    filters.push_back(f);
  }

  for (int count = 0; count < 100; count++) {
    std::vector<shared_ptr<CiphertextImpl<DCRTPoly>>> inners;
    for (int i = 0; i < x.size(); ++i) {
      auto filter = cc->MakeCKKSPackedPlaintext(filters[i]);
      auto i1 = cc->EvalInnerProduct(c, filter, batchSize);
      inners.push_back(i1);
    }

    for (const auto &a : inners) {
      Plaintext result;
      cc->Decrypt(keys.secretKey, a, &result);
      result->SetLength(batchSize);
      // std::cout << result << std::endl;
    }
  }

  // auto res = cc->EvalMerge(inners);

  //  Plaintext result;
  //  std::cout.precision(8);
  //
  //  cc->Decrypt(keys.secretKey, res, &result);
  //  result->SetLength(batchSize);
  //
  //  std::cout << result << std::endl;

  return 0;
}