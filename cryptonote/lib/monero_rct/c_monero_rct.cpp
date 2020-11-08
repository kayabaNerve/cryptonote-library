#include <vector>

#include "pybind11/pybind11.h"
#include "pybind11/stl.h"

#include "crypto/crypto.h"
#include "device/device.hpp"
#include "device/device_default.hpp"

#include "ringct/bulletproofs.h"

#include "ringct/rctTypes.h"
#include "ringct/rctSigs.h"

pybind11::bytes generate_key_image(
    pybind11::bytes priv_key_arg,
    pybind11::bytes pub_key_arg
) {
    crypto::public_key pub_key;
    crypto::secret_key priv_key;
    memcpy(priv_key.data, PYBIND11_BYTES_AS_STRING(priv_key_arg.ptr()), 32);
    memcpy(pub_key.data, PYBIND11_BYTES_AS_STRING(pub_key_arg.ptr()), 32);

    crypto::key_image image;
    crypto::generate_key_image(pub_key, priv_key, image);
    return pybind11::bytes(std::string(image.data, 32));
}

rct::rctSig generate_ringct_signatures(
    pybind11::bytes prefix_hash_arg,
    std::vector<pybind11::tuple> private_keys_arg,
    std::vector<pybind11::bytes> destinations_arg,
    std::vector<pybind11::bytes> amount_keys_arg,
    std::vector<std::vector<std::vector<pybind11::bytes>>> ring_arg,
    std::vector<unsigned int> indexes,
    std::vector<rct::xmr_amount> inputs,
    std::vector<rct::xmr_amount> outputs,
    rct::xmr_amount fee
) {
    //Extract the prefix hash.
    crypto::hash prefix_hash;
    memcpy(prefix_hash.data, PYBIND11_BYTES_AS_STRING(prefix_hash_arg.ptr()), 32);

    //Extract the private keys.
    rct::ctkeyV private_keys(private_keys_arg.size());
    for (uint i = 0; i < private_keys_arg.size(); i++) {
        crypto::secret_key temp_secret;
        memcpy(temp_secret.data, PYBIND11_BYTES_AS_STRING(private_keys_arg[i][0].ptr()), 32);

        rct::ctkey temp_ct;
        rct::key temp_key = rct::sk2rct(temp_secret);
        temp_ct.dest = temp_key;
        memcpy(temp_ct.mask.bytes, PYBIND11_BYTES_AS_STRING(private_keys_arg[i][1].ptr()), 32);
        private_keys[i] = temp_ct;
    }

    //Extract the destination keys.
    rct::keyV destinations(destinations_arg.size());
    for (uint i = 0; i < destinations_arg.size(); i++) {
        crypto::public_key temp_public;
        memcpy(temp_public.data, PYBIND11_BYTES_AS_STRING(destinations_arg[i].ptr()), 32);
        destinations[i] = rct::pk2rct(temp_public);
    }

    //Extract the amount keys (Hs(8rA || i)).
    rct::keyV amount_keys(amount_keys_arg.size());
    for (uint i = 0; i < amount_keys_arg.size(); i++) {
        rct::key temp_key;
        memcpy(temp_key.bytes, PYBIND11_BYTES_AS_STRING(amount_keys_arg[i].ptr()), 32);
        amount_keys[i] = temp_key;
    }

    //Create the ring.
    rct::ctkeyM ring(ring_arg.size());
    for (uint i = 0; i < ring_arg.size(); i++) {
        rct::ctkeyV ring_v(ring_arg[i].size());
        for (uint v = 0; v < ring_arg[i].size(); v++) {
            rct::ctkey temp_ct;
            memcpy(temp_ct.dest.bytes, PYBIND11_BYTES_AS_STRING(ring_arg[i][v][0].ptr()), 32);
            memcpy(temp_ct.mask.bytes, PYBIND11_BYTES_AS_STRING(ring_arg[i][v][1].ptr()), 32);
            ring_v[v] = temp_ct;
        }
        ring[i] = ring_v;
    }

    //Create the RingCT Signatures.
    rct::ctkeyV out_keys;
    return rct::genRctSimple(
        rct::hash2rct(prefix_hash),
        private_keys,
        destinations,
        inputs,
        outputs,
        fee,
        ring,
        amount_keys,
        NULL,
        NULL,
        indexes,
        out_keys,
        {rct::RangeProofPaddedBulletproof, 2},
        hw::get_device("default")
    );
}

rct::rctSig test_ringct_signatures(
    std::vector<pybind11::bytes> amounts_arg,
    std::vector<pybind11::bytes> out_public_keys_arg,

    std::vector<pybind11::bytes> A_arg,
    std::vector<pybind11::bytes> S_arg,
    std::vector<pybind11::bytes> T1_arg,
    std::vector<pybind11::bytes> T2_arg,
    std::vector<pybind11::bytes> taux_arg,
    std::vector<pybind11::bytes> mu_arg,
    std::vector<std::vector<pybind11::bytes>> L_arg,
    std::vector<std::vector<pybind11::bytes>> R_arg,
    std::vector<pybind11::bytes> a_arg,
    std::vector<pybind11::bytes> b_arg,
    std::vector<pybind11::bytes> t_arg,

    std::vector<std::vector<std::vector<pybind11::bytes>>> ss_arg,
    std::vector<pybind11::bytes> cc_arg,
    std::vector<pybind11::bytes> pseudo_outs_arg
) {
    rct::rctSig result;

    result.ecdhInfo.resize(amounts_arg.size());
    for (uint a = 0; a < amounts_arg.size(); a++) {
        memcpy(result.ecdhInfo[a].amount.bytes, PYBIND11_BYTES_AS_STRING(amounts_arg[a].ptr()), 8);
    }

    result.outPk.resize(out_public_keys_arg.size());
    for (uint k = 0; k < out_public_keys_arg.size(); k++) {
        memcpy(result.outPk[k].mask.bytes, PYBIND11_BYTES_AS_STRING(out_public_keys_arg[k].ptr()), 32);
    }

    result.p.bulletproofs.resize(A_arg.size());
    for (uint bp = 0; bp < A_arg.size(); bp++) {
        memcpy(result.p.bulletproofs[bp].A.bytes, PYBIND11_BYTES_AS_STRING(A_arg[bp].ptr()), 32);
        memcpy(result.p.bulletproofs[bp].S.bytes, PYBIND11_BYTES_AS_STRING(S_arg[bp].ptr()), 32);
        memcpy(result.p.bulletproofs[bp].T1.bytes, PYBIND11_BYTES_AS_STRING(T1_arg[bp].ptr()), 32);
        memcpy(result.p.bulletproofs[bp].T2.bytes, PYBIND11_BYTES_AS_STRING(T2_arg[bp].ptr()), 32);

        memcpy(result.p.bulletproofs[bp].taux.bytes, PYBIND11_BYTES_AS_STRING(taux_arg[bp].ptr()), 32);
        memcpy(result.p.bulletproofs[bp].mu.bytes, PYBIND11_BYTES_AS_STRING(mu_arg[bp].ptr()), 32);

        result.p.bulletproofs[bp].L.resize(L_arg[bp].size());
        for (uint i = 0; i < L_arg[bp].size(); i++) {
            memcpy(result.p.bulletproofs[bp].L[i].bytes, PYBIND11_BYTES_AS_STRING(L_arg[bp][i].ptr()), 32);
        }
        result.p.bulletproofs[bp].R.resize(R_arg[bp].size());
        for (uint i = 0; i < R_arg[bp].size(); i++) {
            memcpy(result.p.bulletproofs[bp].R[i].bytes, PYBIND11_BYTES_AS_STRING(R_arg[bp][i].ptr()), 32);
        }

        memcpy(result.p.bulletproofs[bp].a.bytes, PYBIND11_BYTES_AS_STRING(a_arg[bp].ptr()), 32);
        memcpy(result.p.bulletproofs[bp].b.bytes, PYBIND11_BYTES_AS_STRING(b_arg[bp].ptr()), 32);
        memcpy(result.p.bulletproofs[bp].t.bytes, PYBIND11_BYTES_AS_STRING(t_arg[bp].ptr()), 32);
    }

    result.p.MGs.resize(ss_arg.size());
    for (uint mg_i = 0; mg_i < ss_arg.size(); mg_i++) {
        result.p.MGs[mg_i].ss.resize(ss_arg[mg_i].size());
        for (uint ss_i = 0; ss_i < ss_arg[mg_i].size(); ss_i++) {
            result.p.MGs[mg_i].ss[ss_i].resize(ss_arg[mg_i][ss_i].size());
            for (uint ss_i_i = 0; ss_i_i < ss_arg[mg_i][ss_i].size(); ss_i_i++) {
                memcpy(result.p.MGs[mg_i].ss[ss_i][ss_i_i].bytes, PYBIND11_BYTES_AS_STRING(ss_arg[mg_i][ss_i][ss_i_i].ptr()), 32);
            }
        }

        memcpy(result.p.MGs[mg_i].cc.bytes, PYBIND11_BYTES_AS_STRING(cc_arg[mg_i].ptr()), 32);
    }

    result.p.pseudoOuts.resize(pseudo_outs_arg.size());
    for (uint o = 0; o < pseudo_outs_arg.size(); o++) {
        memcpy(result.p.pseudoOuts[o].bytes, PYBIND11_BYTES_AS_STRING(pseudo_outs_arg[o].ptr()), 32);
    }

    return result;
}

PYBIND11_MODULE(c_monero_rct, module) {
    module.doc() = "Python Wrapper for Monero's RingCT library.";

    pybind11::class_<rct::key>(module, "Key")
        .def("__getitem__", pybind11::overload_cast<int>(&rct::key::operator[]));

    pybind11::class_<rct::ctkey>(module, "CTKey")
        .def_readonly("dest", &rct::ctkey::dest)
        .def_readonly("mask", &rct::ctkey::mask);

    pybind11::class_<rct::ecdhTuple>(module, "ECDHTuple")
        .def_readonly("mask", &rct::ecdhTuple::mask)
        .def_readonly("amount", &rct::ecdhTuple::amount);

    pybind11::class_<rct::Bulletproof>(module, "Bulletproof")
        .def_readonly("v", &rct::Bulletproof::V)

        .def_readonly("capital_a", &rct::Bulletproof::A)
        .def_readonly("s", &rct::Bulletproof::S)
        .def_readonly("t1", &rct::Bulletproof::T1)
        .def_readonly("t2", &rct::Bulletproof::T2)

        .def_readonly("taux", &rct::Bulletproof::taux)
        .def_readonly("mu", &rct::Bulletproof::mu)

        .def_readonly("l", &rct::Bulletproof::L)
        .def_readonly("r", &rct::Bulletproof::R)

        .def_readonly("a", &rct::Bulletproof::a)
        .def_readonly("b", &rct::Bulletproof::b)
        .def_readonly("t", &rct::Bulletproof::t);

    pybind11::class_<rct::mgSig>(module, "MGSignature")
        .def_readonly("ss", &rct::mgSig::ss)
        .def_readonly("cc", &rct::mgSig::cc);

    pybind11::class_<rct::rctSigPrunable>(module, "RingCTPrunable")
        .def_readonly("pseudo_outs", &rct::rctSigPrunable::pseudoOuts)
        .def_readonly("bulletproofs", &rct::rctSigPrunable::bulletproofs)
        .def_readonly("MGs", &rct::rctSigPrunable::MGs);

    pybind11::class_<rct::rctSig>(module, "RingCTSignatures")
        .def_readonly("ecdh_info", &rct::rctSig::ecdhInfo)
        .def_readonly("out_public_keys", &rct::rctSig::outPk)

        .def_readonly("prunable", &rct::rctSig::p);

    module.def("generate_key_image", &generate_key_image, "Generate a key image for a one-time key.");
    module.def("generate_ringct_signatures", &generate_ringct_signatures, "Generate RingCT Signatures for the given data.");
    module.def("test_ringct_signatures", &test_ringct_signatures, "Generate RingCT Signatures with the passed in data.");
}
