#include <iostream>
#include <vector>
#include <cmath>
#include <fstream>
#include <string>


#include "seal/seal.h"
#include "utils.h"

using namespace seal;

int main(void){
    // These three are fixed here
    uint64_t effective_bitlength = 19;
    uint64_t hw=8;

    uint64_t client_set=1024;
    uint64_t server_set=1<<20;
    Task task = PSI;
    uint64_t label_byte_size=1;

    uint64_t N=8192;
    
    uint64_t gamma = 1;
    uint64_t mu=1;
    uint64_t num_bins=1;
    uint64_t num_balls=1;

    gamma = ceil(client_set * 1.27 / N);
    
    num_bins = N*gamma;
    num_balls = 3 * server_set;
    
    mu = ceil((float)num_balls/num_bins + 2 * sqrt((float)num_balls*log2(num_bins)/num_bins));

    // ==================================
    // Client Side

    seal::EncryptionParameters* enc_params;

    seal::SEALContext* context;
    seal::KeyGenerator* keygen;
    seal::SecretKey secret_key;
    seal::Evaluator* evaluator;
    seal::Encryptor* encryptor;
    seal::BatchEncoder* batch_encoder;

    Params params(task, mu, gamma, effective_bitlength, hw, label_byte_size);

    enc_params = new EncryptionParameters(scheme_type::bfv);
    enc_params->set_poly_modulus_degree(1 << params.log_poly_modulus_degree);

    // Setting the coeffcient modulus
    // this->enc_params->set_coeff_modulus(CoeffModulus::BFVDefault(1 << log_poly_modulus_degree));
    enc_params->set_coeff_modulus(params.coeff_bits);
    // for (Modulus mod: this->enc_params->coeff_modulus()) {
    //     cout << mod.bit_count() << " ";
    // } cout << endl;

    enc_params->set_plain_modulus(PlainModulus::Batching(1 << params.log_poly_modulus_degree, params.prime_bitlength));

    context = new SEALContext(*(enc_params));
    keygen = new KeyGenerator(*(context));
    secret_key = keygen->secret_key();
    encryptor = new Encryptor(*(context), secret_key);
    batch_encoder = new BatchEncoder(*(context));

    // ==================================
    // Generate keys to send them to the Server

    std::stringstream params_stream;

    enc_params->save(params_stream);
    Serializable<RelinKeys> rlk_client = keygen->create_relin_keys();
    rlk_client.save(params_stream);
    Serializable<GaloisKeys> gal_keys_client = keygen->create_galois_keys();
    gal_keys_client.save(params_stream);
    Serializable<PublicKey> public_key = keygen->create_public_key();
    public_key.save(params_stream);

    // ==================================
    // Server Side

    seal::EncryptionParameters* enc_params_server;
    seal::SEALContext* context_server;

    seal::Evaluator* evaluator_server;
    seal::RelinKeys* rlk_keys_server_server;
    seal::GaloisKeys* gal_keys_server_server;
    seal::PublicKey* public_key_server;
    seal::Encryptor* encryptor_server;
    seal::BatchEncoder* batch_encoder_server;


    enc_params_server = new EncryptionParameters();
    enc_params_server->load(params_stream);

    context_server = new SEALContext(*enc_params);

    rlk_keys_server_server = new RelinKeys();
    gal_keys_server_server = new GaloisKeys();
    public_key_server = new PublicKey();
    rlk_keys_server_server->load(*context_server, params_stream);
    gal_keys_server_server->load(*context_server, params_stream);
    public_key_server->load(*context_server, params_stream);

    batch_encoder_server = new BatchEncoder(*context_server);
    encryptor_server = new Encryptor(*context_server, *public_key_server);
    evaluator_server = new Evaluator(*context_server);
    

    Timer_micro key_timer;
    long key_time;

    uint64_t bins = 1 << params.log_poly_modulus_degree;
    vector<uint64_t> msg(bins);


    std::cout << "Construct message" << std::endl;
    key_timer.start();

    for (int i = 0; i < bins; ++i) {
        msg[i] = i;
    }

    key_time = key_timer.end_and_get();
    std::cout << "done ..." << std::endl;
    std::cout << key_time << " usec" << std::endl;
    std::cout << std::endl;


    std::cout << "Encode msg (make ptxt) in Server" << std::endl;
    key_timer.start();

    Plaintext ptxt1;
    batch_encoder_server->encode(msg, ptxt1);

    key_time = key_timer.end_and_get();
    std::cout << "done ..." << std::endl;
    std::cout << key_time << " usec" << std::endl << std::endl;  


    std::cout << "Encode msg (make ptxt) in Client" << std::endl;
    key_timer.start();

    Plaintext ptxt;
    batch_encoder->encode(msg, ptxt);

    key_time = key_timer.end_and_get();
    std::cout << "done ..." << std::endl;
    std::cout << key_time << " usec" << std::endl << std::endl;   

    
    std::cout << "Encrypt msg (make ctxt)" << std::endl;
    key_timer.start();

    Ciphertext ctxt;
    encryptor->encrypt_symmetric(ptxt, ctxt);

    key_time = key_timer.end_and_get();
    std::cout << "done ..." << std::endl;
    std::cout << key_time << " usec" << std::endl << std::endl;   


    Ciphertext test1, test2;
    encryptor_server->encrypt_zero(test1);
    encryptor_server->encrypt_zero(test2);
    // encryptor->encrypt_zero_symmetric(test1);
    // encryptor->encrypt_zero_symmetric(test2);

    std::cout << "Add ctxt and ctxt" << std::endl;
    key_timer.start();

    evaluator_server->add_inplace(test1, ctxt);

    key_time = key_timer.end_and_get();
    std::cout << "done ..." << std::endl;
    std::cout << key_time << " usec" << std::endl << std::endl;   


    std::cout << "mult ptxt and ctxt" << std::endl;
    key_timer.start();

    evaluator_server->multiply_plain(ctxt, ptxt, test1);

    key_time = key_timer.end_and_get();
    std::cout << "done ..." << std::endl;
    std::cout << key_time << " usec" << std::endl << std::endl;   

    
    std::cout << "mult ctxt and ctxt" << std::endl;
    key_timer.start();

    evaluator_server->multiply(ctxt, test2, test1);

    key_time = key_timer.end_and_get();
    std::cout << "done ..." << std::endl;
    std::cout << key_time << " usec" << std::endl << std::endl;   

    // =============================================

    std::cout << "use sum" << std::endl;
    key_timer.start();

    accumulate(msg.begin(), msg.end(), 0);

    key_time = key_timer.end_and_get();
    std::cout << "done ..." << std::endl;
    std::cout << key_time << " usec" << std::endl << std::endl;   


    Plaintext ptpt;
    batch_encoder->encode(vector<uint64_t>(batch_encoder->slot_count(), 0), ptpt);

    std::cout << "use equal" << std::endl;
    key_timer.start();

    bool bb = (ptxt == ptpt);

    key_time = key_timer.end_and_get();
    std::cout << "done ..." << std::endl;
    std::cout << key_time << " usec" << std::endl << std::endl;  

    std::cout << sizeof(Plaintext) << std::endl;
    std::cout << sizeof(Ciphertext) << std::endl;

    return 0;
}