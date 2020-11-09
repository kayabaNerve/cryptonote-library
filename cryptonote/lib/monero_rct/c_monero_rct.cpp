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
        {rct::RangeProofPaddedBulletproof, 3},
        hw::get_device("default")
    );
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

    pybind11::class_<rct::clsag>(module, "CLSAG")
        .def_readonly("s", &rct::clsag::s)
        .def_readonly("c1", &rct::clsag::c1)
        .def_readonly("D", &rct::clsag::D);

    pybind11::class_<rct::rctSigPrunable>(module, "RingCTPrunable")
        .def_readonly("pseudo_outs", &rct::rctSigPrunable::pseudoOuts)
        .def_readonly("bulletproofs", &rct::rctSigPrunable::bulletproofs)
        .def_readonly("CLSAGs", &rct::rctSigPrunable::CLSAGs);

    pybind11::class_<rct::rctSig>(module, "RingCTSignatures")
        .def_readonly("ecdh_info", &rct::rctSig::ecdhInfo)
        .def_readonly("out_public_keys", &rct::rctSig::outPk)

        .def_readonly("prunable", &rct::rctSig::p);

    module.def("generate_key_image", &generate_key_image, "Generate a key image for a one-time key.");
    module.def("generate_ringct_signatures", &generate_ringct_signatures, "Generate RingCT Signatures for the given data.");
}
