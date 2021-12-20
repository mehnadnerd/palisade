// stolen from
// https://gitlab.com/palisade/palisade-python-demo/-/blob/master/python/lsvm.py
// tests CKKS
#define PROFILE

#include <chrono>
#include <fstream>
#include <iostream>
#include <iterator>

#include "cryptocontextgen.h"
#include "palisade.h"
#include "ckkswrapper.h"

using namespace std;
using namespace lbcrypto;
using namespace pycrypto;

typedef std::vector<double> plaintextv;
typedef std::vector<CiphertextInterfaceType> ciphertextv;

int nextpow2(int in) {
  if (in == 0) {
    return 1;
  }
  int i = 0;
  while (in >>= 1) {
    ++i;
  }
  return i;
}

//############################################
//# Plaintext version of lsvm
//# num - number of inputs to be tested
//# Outputs prediction list

std::vector<double> lsvm_plain_beta_plain_input(
    const std::vector<double>& beta, const std::vector<double>& bias,
    const std::vector<std::vector<double>>& x, const int num) {
  std::vector<double> result;
  result.reserve(num);
  for (int i = 0; i < num; ++i) {
    double acc = 0.0;
    for (int j = 0; j < (int) beta.size(); ++j) {
      acc += beta[j] * x[i][j];
    }
    result.push_back(acc + bias[0]);
  }
  return result;
}

std::vector<CiphertextInterfaceType> lsvm_enc_beta_plain_input(
    CKKSwrapper& crypto, const CiphertextInterfaceType& enc_beta,
    const CiphertextInterfaceType& enc_bias,
    const std::vector<std::vector<double>>& x, int num, int fs) {
  std::vector<CiphertextInterfaceType> result;
  result.reserve(num);
  for (int i = 0; i < num; ++i) {
    auto enc_betaxi = crypto.EvalMultConst(enc_beta, x[i]);
    auto enc_ip = crypto.EvalSum(*enc_betaxi, nextpow2(fs + 1));
    auto enc_svm = crypto.EvalAdd(*enc_ip, enc_bias);
    result.push_back(*enc_svm);
    delete enc_betaxi;
    delete enc_ip;
    delete enc_svm;
  }
  return result;
}

std::vector<double> dec_output(
    CKKSwrapper& crypto, const std::vector<CiphertextInterfaceType>& enc_res,
    int num) {
  std::vector<double> result;
  result.reserve(num);
  for (int i = 0; i < num; ++i) {
    auto dec_res = crypto.Decrypt(enc_res[i]);
    result.push_back(dec_res[0].real());
  }
  return result;
}

std::vector<CiphertextInterfaceType> enc_input(
    CKKSwrapper& crypto, const std::vector<std::vector<double>>& x, int num) {
  std::vector<CiphertextInterfaceType> enc_x;
  enc_x.reserve(num);
  for (int i = 0; i < num; ++i) {
    auto a = crypto.Encrypt(x[i]);
    enc_x.push_back(*a);
    delete a;
  }

  return enc_x;
}

std::vector<CiphertextInterfaceType> lsvm_enc_beta_enc_input(
    CKKSwrapper& crypto, const CiphertextInterfaceType& enc_beta,
    const CiphertextInterfaceType& enc_bias,
    std::vector<CiphertextInterfaceType> enc_x, int num, int fs) {
  std::vector<CiphertextInterfaceType> enc_res;
  enc_res.reserve(num);
  for (int i = 0; i < num; ++i) {
    auto enc_betaxi = crypto.EvalMult(enc_beta, enc_x[i]);
    auto enc_ip = crypto.EvalSum(*enc_betaxi, nextpow2(fs + 1));
    auto enc_svm = crypto.EvalAdd(*enc_ip, enc_bias);
    enc_res.push_back(*enc_svm);
    delete enc_betaxi;
    delete enc_ip;
    delete enc_svm;
  }
  return enc_res;
}

int main(int argc, char** argv) {
  // input
  std::vector<double> beta;
  std::vector<double> bias;
  int features = 0;
  {
    std::vector<double> in;
    auto csv_file = fopen(argv[1], "r");
    char linebuf[256];
    double scale = 1.0;
    while (fgets(linebuf, 256, csv_file) != NULL) {
      char* l;
      l = strtok(linebuf, ",");

      while (l != NULL) {
        if (features == 0) {
          scale = strtod(l, NULL);
        } else {
          in.push_back(strtod(l, NULL));
        }
        features++;
        l = strtok(NULL, ",");
      }
    }
    features -= 2;
    for (int i = 0; i < features; ++i) {
      beta.push_back(in[i] / scale);
    }
    bias.push_back(in[features]);
    fclose(csv_file);
  }

  std::vector<std::vector<double>> x;
  int num_test = 0;
  {
    auto csv_file = fopen(argv[2], "r");
    char linebuf[2048];
    while (fgets(linebuf, 2048, csv_file) != NULL) {
      char* l;
      l = strtok(linebuf, ",");
      std::vector<double> in;

      while (l != NULL) {
        in.push_back(strtod(l, NULL));
        l = strtok(NULL, ",");
      }
      x.push_back(in);
      num_test++;
    }
    fclose(csv_file);
  }

  int max_depth = 1;
  int scale_factor = 50;
  int batch_size = nextpow2(features + 1);
  // read file input

  // enncrypt
  for (int i = 0; i < 10; ++i) {
    CKKSwrapper crypto;
    crypto.KeyGen(max_depth, scale_factor, batch_size);
    auto enc_beta = crypto.Encrypt(beta);
    auto enc_bias = crypto.Encrypt(bias);

    auto res_plain = lsvm_plain_beta_plain_input(beta, bias, x, num_test);
    auto enc_res_plain_input = lsvm_enc_beta_plain_input(
        crypto, *enc_beta, *enc_bias, x, num_test, features);
    auto res_plain_input = dec_output(crypto, enc_res_plain_input, num_test);
    auto enc_x = enc_input(crypto, x, num_test);
    auto enc_res_enc_input = lsvm_enc_beta_enc_input(
        crypto, *enc_beta, *enc_bias, enc_x, num_test, features);
    auto res_enc_input = dec_output(crypto, enc_res_enc_input, num_test);

    //  double sqerr1 = 0.0;
    //  double sqerr2 = 0.0;
    //  for (int i = 0; i < res_plain.size(); ++i) {
    //    double c = res_plain[i];
    //    double r1 = res_plain_input[i];
    //    double r2 = res_enc_input[i];
    //    double e1 = (c - r1) / c;
    //    double e2 = (c - r2) / c;
    //    sqerr1 += e1 * e1;
    //    sqerr2 += e2 * e2;
    //    printf("c 1 2 %f %f %f\n", c, r1, r2);
    //  }
    //  printf("eq %i %f, %f, %lu\n",features, sqerr1, sqerr2,
    //  res_plain.size());
    delete enc_beta;
    delete enc_bias;
  }
}